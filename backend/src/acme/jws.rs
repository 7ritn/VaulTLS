use std::collections::BTreeMap;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ecdsa::EcdsaSig;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::sign::Verifier;
use serde_json::Value;

use super::types::{AcmeError, JwsProtectedHeader, JwsRequest};

pub fn base64url_decode(input: &str) -> Result<Vec<u8>, AcmeError> {
    if input.contains('+') || input.contains('/') {
        return Err(AcmeError::malformed("Invalid base64url encoding: use '-' and '_', not '+' and '/'"));
    }

    let standard = input.replace('-', "+").replace('_', "/");

    let padded = match standard.len() % 4 {
        0 => standard,
        2 => standard + "==",
        3 => standard + "=",
        _ => {
            return Err(AcmeError::malformed("Invalid base64url encoding"));
        }
    };

    openssl::base64::decode_block(&padded)
        .map_err(|_| AcmeError::malformed("Invalid base64url encoding"))
}

pub fn base64url_encode(input: &[u8]) -> String {
    openssl::base64::encode_block(input)
        .replace('\n', "")
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned()
}

pub fn parse_jws(
    body: &str,
) -> Result<(JwsProtectedHeader, Vec<u8>, Vec<u8>, Vec<u8>), AcmeError> {
    let req: JwsRequest = serde_json::from_str(body)
        .map_err(|e| AcmeError::malformed(format!("Invalid JWS JSON: {e}")))?;

    let protected_bytes = base64url_decode(&req.protected)?;
    let header: JwsProtectedHeader = serde_json::from_slice(&protected_bytes)
        .map_err(|e| AcmeError::malformed(format!("Invalid protected header: {e}")))?;

    // Payload may be empty string for POST-as-GET.
    let payload_bytes = if req.payload.is_empty() {
        Vec::new()
    } else {
        base64url_decode(&req.payload)?
    };

    let signature_bytes = base64url_decode(&req.signature)?;

    Ok((header, protected_bytes, payload_bytes, signature_bytes))
}

fn ecdsa_raw_to_der(signature: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let half = signature.len() / 2;
    let r = &signature[..half];
    let s = &signature[half..];

    let r_bn = BigNum::from_slice(r)
        .map_err(|_| AcmeError::malformed("Invalid signature: bad R component"))?;
    let s_bn = BigNum::from_slice(s)
        .map_err(|_| AcmeError::malformed("Invalid signature: bad S component"))?;

    let sig = EcdsaSig::from_private_components(r_bn, s_bn)
        .map_err(|_| AcmeError::malformed("Invalid signature: cannot build ECDSA sig"))?;

    sig.to_der()
        .map_err(|_| AcmeError::malformed("Invalid signature: DER encoding failed"))
}

/// Verify a JWS signature.
///
/// * `alg`          — algorithm string from the protected header (e.g. "ES256", "RS256")
/// * `key_data`     — JWK object (`{"kty":…, "crv":…, "x":…, "y":…}` or `{"kty":…, "n":…, "e":…}`)
/// * `protected_b64`— the raw base64url-encoded protected header string
/// * `payload_b64`  — the raw base64url-encoded payload string
/// * `signature`    — decoded signature bytes
pub fn verify_signature(
    alg: &str,
    key_data: &Value,
    protected_b64: &str,
    payload_b64: &str,
    signature: &[u8],
) -> Result<(), AcmeError> {
    // Signing input is always "{protected}.{payload}" as ASCII bytes.
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signing_input_bytes = signing_input.as_bytes();

    match alg {
        "ES256" => {
            let x_b64 = key_data["x"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("JWK missing x"))?;
            let y_b64 = key_data["y"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("JWK missing y"))?;

            let x_bytes = base64url_decode(x_b64)?;
            let y_bytes = base64url_decode(y_b64)?;

            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|_| AcmeError::server_internal("Failed to create EC group"))?;

            let x_bn = BigNum::from_slice(&x_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK x coordinate"))?;
            let y_bn = BigNum::from_slice(&y_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK y coordinate"))?;

            let mut ctx = BigNumContext::new()
                .map_err(|_| AcmeError::server_internal("BigNumContext failed"))?;

            let mut point = EcPoint::new(&group)
                .map_err(|_| AcmeError::server_internal("Failed to create EC point"))?;

            point
                .set_affine_coordinates_gfp(&group, &x_bn, &y_bn, &mut ctx)
                .map_err(|_| AcmeError::malformed("Invalid EC point coordinates"))?;

            let ec_key = EcKey::from_public_key(&group, &point)
                .map_err(|_| AcmeError::malformed("Failed to construct EC public key"))?;

            ec_key.check_key()
                .map_err(|_| AcmeError::malformed("Invalid EC public key: point check failed"))?;

            let pkey = PKey::from_ec_key(ec_key)
                .map_err(|_| AcmeError::server_internal("Failed to wrap EC key in PKey"))?;

            let der_sig = ecdsa_raw_to_der(signature)?;

            let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
                .map_err(|_| AcmeError::server_internal("Failed to create verifier"))?;

            verifier
                .update(signing_input_bytes)
                .map_err(|_| AcmeError::server_internal("Verifier update failed"))?;

            let valid = verifier
                .verify(&der_sig)
                .map_err(|_| AcmeError::malformed("Signature verification error"))?;

            if !valid {
                return Err(AcmeError::malformed("Signature verification failed"));
            }

            Ok(())
        }

        "RS256" => {
            let n_b64 = key_data["n"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("JWK missing n"))?;
            let e_b64 = key_data["e"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("JWK missing e"))?;

            let n_bytes = base64url_decode(n_b64)?;
            let e_bytes = base64url_decode(e_b64)?;

            let n_bn = BigNum::from_slice(&n_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK n"))?;
            let e_bn = BigNum::from_slice(&e_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK e"))?;

            let rsa = Rsa::from_public_components(n_bn, e_bn)
                .map_err(|_| AcmeError::malformed("Failed to construct RSA public key"))?;

            // Enforce minimum key size of 2048 bits (RFC 8555 / JWA requirement).
            if rsa.size() < 256 {
                return Err(AcmeError::malformed("RSA key must be at least 2048 bits"));
            }

            let pkey = PKey::from_rsa(rsa)
                .map_err(|_| AcmeError::server_internal("Failed to wrap RSA key in PKey"))?;

            let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
                .map_err(|_| AcmeError::server_internal("Failed to create verifier"))?;

            verifier
                .update(signing_input_bytes)
                .map_err(|_| AcmeError::server_internal("Verifier update failed"))?;

            let valid = verifier
                .verify(signature)
                .map_err(|_| AcmeError::malformed("Signature verification error"))?;

            if !valid {
                return Err(AcmeError::malformed("Signature verification failed"));
            }

            Ok(())
        }

        other => Err(AcmeError::malformed(format!(
            "Unsupported algorithm: {other}"
        ))),
    }
}

/// Verify an External Account Binding JWS.
///
/// * `outer_jwk`    — the account public key (JWK) from the outer new-account request
/// * `eab_kid`      — the expected EAB key identifier
/// * `eab_hmac_key` — raw bytes of the HMAC-SHA256 key
/// * `eab_jws`      — the raw EAB JWS value (`{protected, payload, signature}`)
pub fn verify_eab(
    outer_jwk: &Value,
    eab_kid: &str,
    eab_hmac_key: &[u8],
    eab_jws: &Value,
) -> Result<(), AcmeError> {
    let protected_b64 = eab_jws["protected"]
        .as_str()
        .ok_or_else(|| AcmeError::malformed("EAB missing protected"))?;
    let payload_b64 = eab_jws["payload"]
        .as_str()
        .ok_or_else(|| AcmeError::malformed("EAB missing payload"))?;
    let signature_b64 = eab_jws["signature"]
        .as_str()
        .ok_or_else(|| AcmeError::malformed("EAB missing signature"))?;

    let protected_bytes = base64url_decode(protected_b64)?;
    let header: JwsProtectedHeader = serde_json::from_slice(&protected_bytes)
        .map_err(|e| AcmeError::malformed(format!("Invalid EAB protected header: {e}")))?;

    if header.alg != "HS256" {
        return Err(AcmeError::malformed(format!(
            "EAB algorithm must be HS256, got {}",
            header.alg
        )));
    }

    match &header.kid {
        Some(kid) if kid == eab_kid => {}
        Some(kid) => {
            return Err(AcmeError::malformed(format!(
                "EAB kid mismatch: expected {eab_kid}, got {kid}"
            )));
        }
        None => return Err(AcmeError::malformed("EAB protected header missing kid")),
    }

    let payload_bytes = base64url_decode(payload_b64)?;
    let payload_jwk: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AcmeError::malformed(format!("Invalid EAB payload JSON: {e}")))?;

    if &payload_jwk != outer_jwk {
        return Err(AcmeError::malformed(
            "EAB payload does not match account JWK",
        ));
    }

    let signing_input = format!("{protected_b64}.{payload_b64}");

    let hmac_key = PKey::hmac(eab_hmac_key)
        .map_err(|_| AcmeError::server_internal("Failed to create HMAC key"))?;

    let mut signer = Signer::new(MessageDigest::sha256(), &hmac_key)
        .map_err(|_| AcmeError::server_internal("Failed to create HMAC signer"))?;

    signer
        .update(signing_input.as_bytes())
        .map_err(|_| AcmeError::server_internal("HMAC update failed"))?;

    let computed_mac = signer
        .sign_to_vec()
        .map_err(|_| AcmeError::server_internal("HMAC sign failed"))?;

    let provided_mac = base64url_decode(signature_b64)?;

    if !openssl::memcmp::eq(&computed_mac, &provided_mac) {
        return Err(AcmeError::malformed("EAB signature verification failed"));
    }

    Ok(())
}

/// Build an OpenSSL `PKey<Public>` from a JWK value.
///
/// Supports `"ES256"` (P-256) and `"RS256"`.  Used by revocation to compare
/// the provided JWK against the certificate's embedded public key.
pub fn jwk_to_pkey(alg: &str, key_data: &Value) -> Result<PKey<Public>, AcmeError> {
    match alg {
        "ES256" => {
            let x_b64 = key_data["x"].as_str().ok_or_else(|| AcmeError::malformed("JWK missing x"))?;
            let y_b64 = key_data["y"].as_str().ok_or_else(|| AcmeError::malformed("JWK missing y"))?;
            let x_bytes = base64url_decode(x_b64)?;
            let y_bytes = base64url_decode(y_b64)?;

            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|_| AcmeError::server_internal("Failed to create EC group"))?;
            let x_bn = BigNum::from_slice(&x_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK x coordinate"))?;
            let y_bn = BigNum::from_slice(&y_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK y coordinate"))?;
            let mut ctx = BigNumContext::new()
                .map_err(|_| AcmeError::server_internal("BigNumContext failed"))?;
            let mut point = EcPoint::new(&group)
                .map_err(|_| AcmeError::server_internal("Failed to create EC point"))?;
            point.set_affine_coordinates_gfp(&group, &x_bn, &y_bn, &mut ctx)
                .map_err(|_| AcmeError::malformed("Invalid EC point coordinates"))?;
            let ec_key = EcKey::from_public_key(&group, &point)
                .map_err(|_| AcmeError::malformed("Failed to construct EC public key"))?;
            PKey::from_ec_key(ec_key)
                .map_err(|_| AcmeError::server_internal("Failed to wrap EC key in PKey"))
        }
        "RS256" => {
            let n_b64 = key_data["n"].as_str().ok_or_else(|| AcmeError::malformed("JWK missing n"))?;
            let e_b64 = key_data["e"].as_str().ok_or_else(|| AcmeError::malformed("JWK missing e"))?;
            let n_bytes = base64url_decode(n_b64)?;
            let e_bytes = base64url_decode(e_b64)?;
            let n_bn = BigNum::from_slice(&n_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK n"))?;
            let e_bn = BigNum::from_slice(&e_bytes)
                .map_err(|_| AcmeError::malformed("Invalid JWK e"))?;
            let rsa = Rsa::from_public_components(n_bn, e_bn)
                .map_err(|_| AcmeError::malformed("Failed to construct RSA public key"))?;
            PKey::from_rsa(rsa)
                .map_err(|_| AcmeError::server_internal("Failed to wrap RSA key in PKey"))
        }
        other => Err(AcmeError::malformed(format!("Unsupported algorithm: {other}"))),
    }
}

pub fn jwk_thumbprint(jwk: &Value) -> Result<String, AcmeError> {
    let kty = jwk["kty"]
        .as_str()
        .ok_or_else(|| AcmeError::malformed("JWK missing kty"))?;

    let canonical = match kty {
        "EC" => {
            let crv = jwk["crv"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("EC JWK missing crv"))?;
            let x = jwk["x"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("EC JWK missing x"))?;
            let y = jwk["y"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("EC JWK missing y"))?;

            let mut map = BTreeMap::new();
            map.insert("crv", crv);
            map.insert("kty", "EC");
            map.insert("x", x);
            map.insert("y", y);
            serde_json::to_string(&map)
                .map_err(|_| AcmeError::server_internal("Failed to serialize thumbprint JSON"))?
        }

        "RSA" => {
            let e = jwk["e"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("RSA JWK missing e"))?;
            let n = jwk["n"]
                .as_str()
                .ok_or_else(|| AcmeError::malformed("RSA JWK missing n"))?;

            let mut map = BTreeMap::new();
            map.insert("e", e);
            map.insert("kty", "RSA");
            map.insert("n", n);
            serde_json::to_string(&map)
                .map_err(|_| AcmeError::server_internal("Failed to serialize thumbprint JSON"))?
        }

        other => {
            return Err(AcmeError::malformed(format!(
                "Unsupported JWK kty: {other}"
            )));
        }
    };

    let digest = openssl::hash::hash(MessageDigest::sha256(), canonical.as_bytes())
        .map_err(|_| AcmeError::server_internal("SHA-256 hash failed"))?;

    Ok(base64url_encode(&digest))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_roundtrip() {
        let original = b"hello world \x00\xff\xfe";
        let encoded = base64url_encode(original);
        // Must not contain standard base64 padding or URL-unsafe chars.
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base64url_known_vector() {
        assert_eq!(base64url_decode("").unwrap(), b"");
        assert_eq!(base64url_decode("Zg").unwrap(), b"f");
    }

    #[test]
    fn test_jwk_thumbprint_ec() {
        let jwk: Value = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "use": "sig"
        });
        // Should not error.
        let thumb = jwk_thumbprint(&jwk).unwrap();
        // Expected thumbprint: SHA-256 of canonical JSON, base64url-encoded.
        // Verified independently: echo -n '{"crv":"P-256","kty":"EC","x":"...","y":"..."}' | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=\n'
        assert_eq!(thumb, "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
    }

    #[test]
    fn test_parse_jws_structure() {
        let header_json = r#"{"alg":"ES256","nonce":"abc","url":"https://example.com/acme/new-acct","jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"}}"#;
        let protected = base64url_encode(header_json.as_bytes());
        let payload = base64url_encode(b"{}");
        let body = format!(
            r#"{{"protected":"{protected}","payload":"{payload}","signature":"AAAA"}}"#
        );

        let (header, raw, _payload_bytes, _sig) = parse_jws(&body).unwrap();
        assert_eq!(header.alg, "ES256");
        assert_eq!(header.nonce.as_deref(), Some("abc"));
        assert_eq!(raw, header_json.as_bytes());
    }
}
