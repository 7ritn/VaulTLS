//! Tests for selectable ECDSA key algorithms (P-256 / P-384) across the whole
//! TLS chain: root CA, intermediate CA and leaf certificates (issue #281).

use anyhow::Result;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509;
use rocket::http::{ContentType, Status};
use serde_json::json;
use vaultls::certs::common::Certificate;
use vaultls::data::api::{CreateCARequest, CreateUserCertificateRequest, SetupRequest};
use vaultls::data::enums::{CAType, CertificateRenewMethod, CertificateType, KeyAlgorithm, TimespanUnit};
use crate::api::api_test_functionality::establish_tls_connection;
use crate::common::constants::*;
use crate::common::test_client::VaulTLSClient;

const P256: Nid = Nid::X9_62_PRIME256V1;
const P384: Nid = Nid::SECP384R1;

/// Sets up a fresh instance whose root CA uses the given key algorithm, and logs in.
async fn setup_with_key_algorithm(key_algorithm: Option<KeyAlgorithm>) -> VaulTLSClient {
    let client = VaulTLSClient::new().await;
    let setup_data = SetupRequest {
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: TEST_CA_NAME.to_string(),
        validity_duration: Some(2),
        validity_unit: Some(TimespanUnit::Year),
        password: Some(TEST_PASSWORD.to_string()),
        default_language: None,
        key_algorithm,
    };
    let response = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data).unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    drop(response);
    client.login(TEST_USER_EMAIL, TEST_PASSWORD).await.unwrap();
    client
}

async fn create_tls_ca(
    client: &VaulTLSClient,
    name: &str,
    parent_id: Option<i64>,
    key_algorithm: Option<KeyAlgorithm>,
) -> Result<i64> {
    let ca_request = CreateCARequest {
        ca_name: name.into(),
        ca_type: CAType::TLS,
        validity_duration: Some(1),
        validity_unit: Some(TimespanUnit::Year),
        parent_id,
        key_algorithm,
    };
    let response = client
        .post("/certificates/ca")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&ca_request)?)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
}

async fn create_tls_cert(
    client: &VaulTLSClient,
    cert_type: CertificateType,
    ca_id: Option<i64>,
    key_algorithm: Option<KeyAlgorithm>,
) -> Result<Certificate> {
    let usage_limit = match cert_type {
        CertificateType::TLSServer => Some(vec![TEST_SERVER_CERT_DNS_NAME.to_string()]),
        _ => None,
    };
    let cert_req = CreateUserCertificateRequest {
        cert_name: TEST_CLIENT_CERT_NAME.into(),
        validity_duration: Some(1),
        validity_unit: Some(TimespanUnit::Month),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        cert_password: Some(TEST_PASSWORD.to_string()),
        cert_type: Some(cert_type),
        usage_limit,
        renew_method: Some(CertificateRenewMethod::None),
        ca_id,
        key_algorithm,
    };
    let response = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?)
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
}

async fn download_ca(client: &VaulTLSClient, ca_id: i64) -> Result<X509> {
    let pem = client.download_cert(&format!("ca/{ca_id}")).await?;
    Ok(X509::from_pem(&pem)?)
}

async fn download_leaf(client: &VaulTLSClient, cert_id: i64) -> Result<X509> {
    let der = client.download_cert(&cert_id.to_string()).await?;
    let parsed = Pkcs12::from_der(&der)?.parse2(TEST_PASSWORD)?;
    Ok(parsed.cert.expect("No certificate in PKCS#12"))
}

fn curve_of(cert: &X509) -> Nid {
    cert.public_key().unwrap()
        .ec_key().expect("Not an EC key")
        .group().curve_name().expect("Unnamed curve")
}

/// Returns whether `cert` carries a valid signature from `issuer`.
fn signed_by(cert: &X509, issuer: &X509) -> bool {
    let key = issuer.public_key().unwrap();
    cert.verify(&key).unwrap()
}

fn signature_nid(cert: &X509) -> Nid {
    cert.signature_algorithm().object().nid()
}

#[tokio::test]
async fn test_default_key_algorithm_is_p256() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let root = download_ca(&client, 1).await?;
    assert_eq!(curve_of(&root), P256);
    assert_eq!(signature_nid(&root), Nid::ECDSA_WITH_SHA256);

    let leaf = download_leaf(&client, 1).await?;
    assert_eq!(curve_of(&leaf), P256);
    assert_eq!(signature_nid(&leaf), Nid::ECDSA_WITH_SHA256);
    Ok(())
}

#[tokio::test]
async fn test_setup_with_p384_root_ca() -> Result<()> {
    let client = setup_with_key_algorithm(Some(KeyAlgorithm::EcdsaP384)).await;

    let root = download_ca(&client, 1).await?;
    assert_eq!(curve_of(&root), P384);
    assert_eq!(signature_nid(&root), Nid::ECDSA_WITH_SHA384);
    assert!(signed_by(&root, &root));
    Ok(())
}

#[tokio::test]
async fn test_setup_with_explicit_p256_root_ca() -> Result<()> {
    let client = setup_with_key_algorithm(Some(KeyAlgorithm::EcdsaP256)).await;

    let root = download_ca(&client, 1).await?;
    assert_eq!(curve_of(&root), P256);
    assert_eq!(signature_nid(&root), Nid::ECDSA_WITH_SHA256);
    Ok(())
}

#[tokio::test]
async fn test_create_p384_root_ca() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let ca_id = create_tls_ca(&client, "P-384 Root", None, Some(KeyAlgorithm::EcdsaP384)).await?;

    let root = download_ca(&client, ca_id).await?;
    assert_eq!(curve_of(&root), P384);
    assert_eq!(signature_nid(&root), Nid::ECDSA_WITH_SHA384);
    Ok(())
}

#[tokio::test]
async fn test_p384_chain_inherits_algorithm_from_issuer() -> Result<()> {
    // Root is P-384; intermediate and leaf do not specify an algorithm.
    let client = setup_with_key_algorithm(Some(KeyAlgorithm::EcdsaP384)).await;
    let intermediate_id = create_tls_ca(&client, "Intermediate", Some(1), None).await?;
    let cert = create_tls_cert(&client, CertificateType::TLSClient, Some(intermediate_id), None).await?;

    let root = download_ca(&client, 1).await?;
    let intermediate = download_ca(&client, intermediate_id).await?;
    let leaf = download_leaf(&client, cert.id).await?;

    assert_eq!(curve_of(&intermediate), P384);
    assert_eq!(signature_nid(&intermediate), Nid::ECDSA_WITH_SHA384);
    assert!(signed_by(&intermediate, &root));

    assert_eq!(curve_of(&leaf), P384);
    assert_eq!(signature_nid(&leaf), Nid::ECDSA_WITH_SHA384);
    assert!(signed_by(&leaf, &intermediate));
    Ok(())
}

#[tokio::test]
async fn test_p256_root_with_explicit_p384_intermediate_and_leaf() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let intermediate_id = create_tls_ca(&client, "Intermediate", Some(1), Some(KeyAlgorithm::EcdsaP384)).await?;
    let cert = create_tls_cert(&client, CertificateType::TLSServer, Some(intermediate_id), Some(KeyAlgorithm::EcdsaP384)).await?;

    let root = download_ca(&client, 1).await?;
    let intermediate = download_ca(&client, intermediate_id).await?;
    let leaf = download_leaf(&client, cert.id).await?;

    assert_eq!(curve_of(&root), P256);
    // The signature algorithm follows the issuer's key, not the subject's.
    assert_eq!(curve_of(&intermediate), P384);
    assert_eq!(signature_nid(&intermediate), Nid::ECDSA_WITH_SHA256);
    assert!(signed_by(&intermediate, &root));

    assert_eq!(curve_of(&leaf), P384);
    assert_eq!(signature_nid(&leaf), Nid::ECDSA_WITH_SHA384);
    assert!(signed_by(&leaf, &intermediate));
    Ok(())
}

#[tokio::test]
async fn test_p384_ca_with_explicit_p256_leaf() -> Result<()> {
    let client = setup_with_key_algorithm(Some(KeyAlgorithm::EcdsaP384)).await;
    let intermediate_id = create_tls_ca(&client, "Intermediate", Some(1), Some(KeyAlgorithm::EcdsaP256)).await?;
    let direct = create_tls_cert(&client, CertificateType::TLSClient, Some(1), Some(KeyAlgorithm::EcdsaP256)).await?;
    let inherited = create_tls_cert(&client, CertificateType::TLSClient, Some(intermediate_id), None).await?;

    let root = download_ca(&client, 1).await?;
    let intermediate = download_ca(&client, intermediate_id).await?;
    assert_eq!(curve_of(&intermediate), P256);
    assert_eq!(signature_nid(&intermediate), Nid::ECDSA_WITH_SHA384);
    assert!(signed_by(&intermediate, &root));

    let direct_leaf = download_leaf(&client, direct.id).await?;
    assert_eq!(curve_of(&direct_leaf), P256);
    assert_eq!(signature_nid(&direct_leaf), Nid::ECDSA_WITH_SHA384);
    assert!(signed_by(&direct_leaf, &root));

    // Leaf below the P-256 intermediate inherits P-256.
    let inherited_leaf = download_leaf(&client, inherited.id).await?;
    assert_eq!(curve_of(&inherited_leaf), P256);
    assert_eq!(signature_nid(&inherited_leaf), Nid::ECDSA_WITH_SHA256);
    assert!(signed_by(&inherited_leaf, &intermediate));
    Ok(())
}

#[tokio::test]
async fn test_key_algorithm_json_wire_format() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    // 1 = ECDSA P-384
    let body = json!({
        "ca_name": {"cn": "Wire CA"},
        "ca_type": 0,
        "parent_id": null,
        "key_algorithm": 1
    });
    let response = client
        .post("/certificates/ca")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let ca_id: i64 = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(curve_of(&download_ca(&client, ca_id).await?), P384);

    // Unknown algorithms are rejected.
    let body = json!({
        "ca_name": {"cn": "Bad CA"},
        "ca_type": 0,
        "key_algorithm": 42
    });
    let response = client
        .post("/certificates/ca")
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    assert!(response.status().class().is_client_error());
    Ok(())
}

#[tokio::test]
async fn test_tls_connection_with_p384_chain() -> Result<()> {
    let client = setup_with_key_algorithm(Some(KeyAlgorithm::EcdsaP384)).await;
    let client_cert = create_tls_cert(&client, CertificateType::TLSClient, None, None).await?;
    let server_cert = create_tls_cert(&client, CertificateType::TLSServer, None, None).await?;

    let ca_pem = client.download_cert("ca").await?;
    let client_p12 = client.download_cert(&client_cert.id.to_string()).await?;
    let server_p12 = client.download_cert(&server_cert.id.to_string()).await?;

    assert_eq!(curve_of(&download_leaf(&client, server_cert.id).await?), P384);
    establish_tls_connection(&ca_pem, &client_p12, &server_p12, None).await?;
    Ok(())
}
