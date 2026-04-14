use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};
use rand_core::Rng;
use tracing::{error, info};
use rocket::{get, head, post, routes, State};
use rocket::data::{Data, FromData, ToByteUnit, Outcome as DataOutcome};
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::Request;
use serde_json::Value;
use crate::acme::types::AcmeOrderRow;
use crate::acme::domain::check_domains;
use crate::acme::client_ip::ClientIp;
use crate::acme::guard::AcmeEnabled;
use crate::acme::jws::{base64url_decode, base64url_encode, jwk_thumbprint, jwk_to_pkey, parse_jws, verify_eab, verify_signature};
use crate::acme::types::{
    AcmeAuthorization, AcmeChallenge, AcmeCreatedResponse, AcmeError, AcmeIdentifier, AcmeOrder,
    AcmePemResponse, Directory, DirectoryMeta,
};
use crate::certs::common::Certificate;
use crate::acme::domain::is_valid_dns_name;
use crate::certs::tls_cert::TLSCertificateBuilder;
use crate::data::enums::{CertificateRenewMethod, CertificateType, TimespanUnit};
use crate::data::objects::{AppState, Name};
use crate::notification::notifier::notify_admins_acme_issued;

static HTTP_CHALLENGE_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
static DOH_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

fn challenge_http_client() -> &'static reqwest::Client {
    HTTP_CHALLENGE_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build HTTP challenge client")
    })
}

fn doh_client() -> &'static reqwest::Client {
    DOH_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build DoH client")
    })
}

fn build_udp_resolver(addr: &str) -> Result<hickory_resolver::TokioResolver, String> {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::proto::xfer::Protocol;
    use hickory_resolver::Resolver;
    use std::net::{IpAddr, SocketAddr};

    if addr.is_empty() {
        return hickory_resolver::TokioResolver::builder_tokio()
            .map(|b| b.build())
            .map_err(|e| format!("Failed to read system DNS config: {e}"));
    }

    let ip: IpAddr = addr.parse()
        .map_err(|_| format!("Invalid DNS resolver address: {addr}"))?;
    let socket_addr = SocketAddr::new(ip, 53);
    let ns = NameServerConfig::new(socket_addr, Protocol::Udp);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    Ok(Resolver::builder_with_config(config, TokioConnectionProvider::default()).build())
}

fn build_dot_resolver(addr: &str) -> Result<hickory_resolver::TokioResolver, String> {
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::proto::xfer::Protocol;
    use hickory_resolver::Resolver;
    use std::net::{IpAddr, SocketAddr};

    let (addr_part, tls_name_opt) = match addr.find('#') {
        Some(idx) => (&addr[..idx], Some(addr[idx + 1..].to_string())),
        None => (addr, None),
    };

    let (ip_str, port) = if let Some(colon) = addr_part.rfind(':') {
        let port_str = &addr_part[colon + 1..];
        match port_str.parse::<u16>() {
            Ok(p) => (&addr_part[..colon], p),
            Err(_) => (addr_part, 853u16),
        }
    } else {
        (addr_part, 853u16)
    };

    let ip: IpAddr = ip_str.parse()
        .map_err(|_| format!("Invalid DoT IP address: {ip_str}"))?;
    let socket_addr = SocketAddr::new(ip, port);
    let tls_name = tls_name_opt.unwrap_or_else(|| ip_str.to_string());

    let mut ns = NameServerConfig::new(socket_addr, Protocol::Tls);
    ns.tls_dns_name = Some(tls_name);
    let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
    Ok(Resolver::builder_with_config(config, TokioConnectionProvider::default()).build())
}

async fn validate_dns01_doh(domain: &str, expected_value: &str, url: &str) -> bool {
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_resolver::proto::rr::{Name, RData, RecordType};

    let lookup_name = format!("_acme-challenge.{}.", domain);
    let name = match Name::from_ascii(&lookup_name) {
        Ok(n) => n,
        Err(e) => {
            error!("Invalid DNS name for DoH query: {e}");
            return false;
        }
    };

    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::TXT);

    let mut message = Message::new();
    message.set_id(1);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);
    message.add_query(query);

    let wire_bytes = match message.to_vec() {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to encode DNS query for DoH: {e}");
            return false;
        }
    };

    let resp = match doh_client()
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(wire_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("DoH request to {url} failed: {e}");
            return false;
        }
    };

    if !resp.status().is_success() {
        error!("DoH endpoint {url} returned status {}", resp.status());
        return false;
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read DoH response body: {e}");
            return false;
        }
    };

    let response = match Message::from_vec(&bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to parse DoH response: {e}");
            return false;
        }
    };

    response.answers().iter().any(|record| {
        if let RData::TXT(txt) = record.data() {
            let record_text: String = txt.iter()
                .map(|data| String::from_utf8_lossy(data).to_string())
                .collect();
            record_text == expected_value
        } else {
            false
        }
    })
}

async fn validate_dns01(domain: &str, expected_value: &str, resolver_addr: &str) -> bool {
    if resolver_addr.starts_with("https://") {
        return validate_dns01_doh(domain, expected_value, resolver_addr).await;
    }

    let resolver_result = if let Some(addr) = resolver_addr.strip_prefix("tls://") {
        build_dot_resolver(addr)
    } else {
        build_udp_resolver(resolver_addr)
    };

    let resolver = match resolver_result {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build DNS resolver: {e}");
            return false;
        }
    };

    let lookup_name = format!("_acme-challenge.{domain}.");
    match resolver.txt_lookup(&lookup_name).await {
        Ok(records) => records.iter().any(|txt| {
            let record_text: String = txt.iter()
                .map(|data| String::from_utf8_lossy(data).to_string())
                .collect();
            record_text == expected_value
        }),
        Err(_) => false,
    }
}

pub struct JoseBody(pub String);

#[rocket::async_trait]
impl<'r> FromData<'r> for JoseBody {
    type Error = AcmeError;

    async fn from_data(_req: &'r Request<'_>, data: Data<'r>) -> DataOutcome<'r, Self> {
        let limit = 1.mebibytes();
        match data.open(limit).into_string().await {
            Ok(s) if s.is_complete() => DataOutcome::Success(JoseBody(s.into_inner())),
            Ok(_) => DataOutcome::Error((Status::PayloadTooLarge, AcmeError::malformed("Request body too large"))),
            Err(_) => DataOutcome::Error((Status::InternalServerError, AcmeError::server_internal("Failed to read body"))),
        }
    }
}

fn make_directory(base: &str) -> Directory {
    Directory {
        new_nonce: format!("{base}/api/acme/new-nonce"),
        new_account: format!("{base}/api/acme/new-account"),
        new_order: format!("{base}/api/acme/new-order"),
        revoke_cert: format!("{base}/api/acme/revoke-cert"),
        meta: DirectoryMeta { external_account_required: true },
    }
}

async fn authenticate_jws(
    state: &AppState,
    body: &str,
    expected_url: &str,
) -> Result<(i64, Vec<u8>), AcmeError> {
    let (header, _protected_bytes, payload_bytes, signature) = parse_jws(body)?;

    if header.jwk.is_some() && header.kid.is_some() {
        return Err(AcmeError::malformed("JWS protected header must not contain both jwk and kid"));
    }

    let nonce = header.nonce.as_deref().unwrap_or("");
    let valid = state.db.validate_and_delete_nonce(nonce.to_string()).await
        .map_err(|_| AcmeError::server_internal("Nonce validation failed"))?;
    if !valid {
        return Err(AcmeError::bad_nonce("Nonce is invalid or already used"));
    }

    match header.url.as_deref() {
        Some(url) if url == expected_url => {}
        Some(_) => return Err(AcmeError::unauthorized("JWS url mismatch")),
        None => return Err(AcmeError::malformed("JWS protected header missing url")),
    }

    let kid = header.kid.ok_or_else(|| AcmeError::malformed("Missing kid in protected header"))?;
    let base = state.settings.get_vaultls_url();
    let expected_kid_prefix = format!("{base}/api/acme/account/");
    if !kid.starts_with(&expected_kid_prefix) {
        return Err(AcmeError::malformed("Invalid kid: unexpected URL prefix"));
    }
    let account_id: i64 = kid[expected_kid_prefix.len()..]
        .parse()
        .map_err(|_| AcmeError::malformed("Invalid kid: non-numeric account id"))?;

    let account = state.db.get_acme_account(account_id).await
        .map_err(|_| AcmeError::account_does_not_exist())?;

    if account.status != "valid" {
        return Err(AcmeError::unauthorized("Account is not active"));
    }

    let jwk_str = account.acme_jwk.ok_or_else(AcmeError::account_does_not_exist)?;
    let jwk: Value = serde_json::from_str(&jwk_str)
        .map_err(|_| AcmeError::server_internal("Stored JWK is invalid"))?;

    let req: crate::acme::types::JwsRequest = serde_json::from_str(body)
        .map_err(|e| AcmeError::malformed(format!("Invalid JWS: {e}")))?;

    verify_signature(&header.alg, &jwk, &req.protected, &req.payload, &signature)?;

    Ok((account_id, payload_bytes))
}

fn ms_to_rfc3339(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn parse_authz_id(id: &str) -> Result<(i64, usize), AcmeError> {
    let parts: Vec<&str> = id.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(AcmeError::malformed("Invalid authorization ID format"));
    }
    let order_id: i64 = parts[0].parse()
        .map_err(|_| AcmeError::malformed("Invalid authorization ID"))?;
    let domain_idx: usize = parts[1].parse()
        .map_err(|_| AcmeError::malformed("Invalid authorization ID"))?;
    Ok((order_id, domain_idx))
}

fn order_row_to_response(row: &AcmeOrderRow, base: &str) -> AcmeOrder {
    let identifiers: Vec<AcmeIdentifier> = serde_json::from_str(&row.identifiers).unwrap_or_default();
    let authz_urls: Vec<String> = (0..identifiers.len())
        .map(|i| format!("{base}/api/acme/authz/{}-{i}", row.id))
        .collect();
    AcmeOrder {
        status: row.status.clone(),
        expires: ms_to_rfc3339(row.expires),
        identifiers,
        authorizations: authz_urls,
        finalize: format!("{base}/api/acme/order/{}/finalize", row.id),
        certificate: row.certificate_id.map(|cid| format!("{base}/api/acme/cert/{cid}")),
    }
}

#[get("/directory")]
pub(crate) async fn get_directory(state: &State<AppState>, _acme: AcmeEnabled) -> Json<Directory> {
    let base = state.settings.get_vaultls_url();
    Json(make_directory(&base))
}

#[head("/new-nonce")]
pub(crate) async fn new_nonce_head(_acme: AcmeEnabled) -> Status {
    Status::Ok
}

#[get("/new-nonce")]
pub(crate) async fn new_nonce_get(_acme: AcmeEnabled) -> Status {
    Status::NoContent
}

#[post("/new-account", data = "<body>")]
pub(crate) async fn new_account(
    state: &State<AppState>,
    body: JoseBody,
    _acme: AcmeEnabled,
) -> Result<AcmeCreatedResponse, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/new-account");

    let (header, _protected_bytes, payload_bytes, signature) = parse_jws(&body.0)?;

    let nonce = header.nonce.as_deref().unwrap_or("");
    let valid = state.db.validate_and_delete_nonce(nonce.to_string()).await
        .map_err(|_| AcmeError::server_internal("Nonce validation failed"))?;
    if !valid {
        return Err(AcmeError::bad_nonce("Nonce is invalid or already used"));
    }

    match header.url.as_deref() {
        Some(url) if url == expected_url => {}
        Some(_) => return Err(AcmeError::unauthorized("JWS url mismatch")),
        None => return Err(AcmeError::malformed("JWS protected header missing url")),
    }

    if header.kid.is_some() {
        return Err(AcmeError::malformed("new-account request must use jwk, not kid"));
    }
    if header.jwk.is_some() && header.kid.is_some() {
        return Err(AcmeError::malformed("JWS protected header must not contain both jwk and kid"));
    }

    let jwk = header.jwk.ok_or_else(|| AcmeError::malformed("Missing jwk in protected header for new-account"))?;

    let req_parsed: crate::acme::types::JwsRequest = serde_json::from_str(&body.0)
        .map_err(|e| AcmeError::malformed(format!("Invalid JWS: {e}")))?;
    verify_signature(&header.alg, &jwk, &req_parsed.protected, &req_parsed.payload, &signature)?;

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AcmeError::malformed(format!("Invalid payload: {e}")))?;

    let eab_jws = payload.get("externalAccountBinding")
        .ok_or_else(|| AcmeError::malformed("externalAccountBinding is required"))?;

    let eab_kid = eab_jws["protected"]
        .as_str()
        .and_then(|p| base64url_decode(p).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|h| h["kid"].as_str().map(|s| s.to_string()))
        .ok_or_else(|| AcmeError::malformed("Cannot extract EAB kid"))?;

    let account = state.db.get_acme_account_by_eab_kid(eab_kid.clone()).await
        .map_err(|_| AcmeError::malformed("EAB key ID not found"))?;

    if !matches!(account.status.as_str(), "valid" | "pending") {
        return Err(AcmeError::unauthorized("Account cannot be used"));
    }

    verify_eab(&jwk, &eab_kid, &account.eab_hmac_key, eab_jws)?;

    let jwk_str = serde_json::to_string(&jwk)
        .map_err(|_| AcmeError::server_internal("Failed to serialize JWK"))?;

    let thumbprint = jwk_thumbprint(&jwk)?;

    let final_account = if account.acme_jwk.is_some() {
        account.clone()
    } else {
        if let Ok(existing) = state.db.get_acme_account_by_jwk_thumbprint(thumbprint.clone()).await {
            if existing.id != account.id {
                return Err(AcmeError::malformed("This key is already registered to another account"));
            }
        }

        let contacts = payload["contact"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","))
            .unwrap_or_default();

        state.db.set_acme_account_jwk(account.id, jwk_str, contacts, thumbprint).await
            .map_err(|_| AcmeError::server_internal("Failed to register account"))?;

        state.db.get_acme_account(account.id).await
            .map_err(|_| AcmeError::server_internal("Failed to retrieve account"))?
    };

    let account_url = format!("{base}/api/acme/account/{}", final_account.id);

    let resp_body = serde_json::json!({
        "status": final_account.status,
        "contact": final_account.contacts.split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>(),
        "orders": format!("{base}/api/acme/orders/{}", final_account.id),
    });

    let body_bytes = serde_json::to_vec(&resp_body)
        .map_err(|_| AcmeError::server_internal("Serialization failed"))?;

    Ok(AcmeCreatedResponse { location: account_url, body: body_bytes })
}

#[post("/new-order", data = "<body>")]
pub(crate) async fn new_order(
    state: &State<AppState>,
    body: JoseBody,
    _acme: AcmeEnabled,
    client_ip: ClientIp,
) -> Result<AcmeCreatedResponse, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/new-order");
    let (account_id, payload_bytes) = authenticate_jws(state, &body.0, &expected_url).await?;

    let account = state.db.get_acme_account(account_id).await
        .map_err(|_| AcmeError::server_internal("Account lookup failed"))?;

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AcmeError::malformed(format!("Invalid payload: {e}")))?;

    let identifiers: Vec<AcmeIdentifier> = payload["identifiers"]
        .as_array()
        .ok_or_else(|| AcmeError::malformed("Missing identifiers"))?
        .iter()
        .map(|v| {
            let t = v["type"].as_str().unwrap_or("dns").to_string();
            let val = v["value"].as_str().unwrap_or("").to_string();
            AcmeIdentifier { identifier_type: t, value: val, token: String::new(), status: "pending".to_string() }
        })
        .collect();

    if identifiers.is_empty() {
        return Err(AcmeError::malformed("At least one identifier required"));
    }

    for ident in &identifiers {
        if ident.identifier_type != "dns" {
            return Err(AcmeError::malformed(
                format!("Unsupported identifier type: {}; only 'dns' is supported", ident.identifier_type)
            ));
        }
        if ident.value.is_empty() {
            return Err(AcmeError::malformed("Identifier value must not be empty"));
        }
        if !is_valid_dns_name(&ident.value) {
            return Err(AcmeError::rejected_identifier(
                format!("Invalid DNS name: {}", ident.value)
            ));
        }
    }

    let requested_domains: Vec<String> = identifiers.iter().map(|i| i.value.clone()).collect();
    if !check_domains(&account.allowed_domains, &requested_domains) {
        return Err(AcmeError::rejected_identifier(
            "One or more requested domains are not permitted for this account".to_string()
        ));
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Rate limit: max 20 orders per account per 24 hours.
    // let recent_count = state.db.count_recent_orders_for_account(account_id, 86_400_000).await
    //     .map_err(|_| AcmeError::server_internal("Rate limit check failed"))?;
    // if recent_count >= 20 {
    //     return Err(AcmeError::malformed("Order rate limit exceeded: max 20 orders per 24 hours per account"));
    // }

    let expires_ms = now_ms + 86_400_000_i64;
    let not_after_ms = now_ms + 90 * 86_400_000_i64;

    let identifiers_with_tokens: Vec<crate::acme::types::AcmeIdentifier> = identifiers
        .into_iter()
        .map(|mut ident| {
            let mut token_bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut token_bytes);
            ident.token = base64url_encode(&token_bytes);
            ident
        })
        .collect();

    let identifiers_db: Vec<serde_json::Value> = identifiers_with_tokens.iter().map(|i| {
        serde_json::json!({
            "type": i.identifier_type,
            "value": i.value,
            "token": i.token,
            "status": i.status,
        })
    }).collect();
    let identifiers_json = serde_json::to_string(&identifiers_db)
        .map_err(|_| AcmeError::server_internal("Serialization failed"))?;

    let order_id = state.db.insert_acme_order(
        account_id,
        identifiers_json,
        not_after_ms,
        expires_ms,
        Some(client_ip.0),
    ).await.map_err(|_| AcmeError::server_internal("Failed to create order"))?;

    let authz_urls: Vec<String> = (0..identifiers_with_tokens.len())
        .map(|i| format!("{base}/api/acme/authz/{order_id}-{i}"))
        .collect();

    let order = AcmeOrder {
        status: "pending".to_string(),
        expires: ms_to_rfc3339(expires_ms),
        identifiers: identifiers_with_tokens,
        authorizations: authz_urls,
        finalize: format!("{base}/api/acme/order/{order_id}/finalize"),
        certificate: None,
    };

    let order_url = format!("{base}/api/acme/order/{order_id}");
    let body_bytes = serde_json::to_vec(&order)
        .map_err(|_| AcmeError::server_internal("Serialization failed"))?;

    Ok(AcmeCreatedResponse { location: order_url, body: body_bytes })
}

#[post("/order/<id>", data = "<body>")]
pub(crate) async fn get_order(
    state: &State<AppState>,
    body: JoseBody,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<Json<AcmeOrder>, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/order/{id}");
    let (account_id, _payload) = authenticate_jws(state, &body.0, &expected_url).await?;

    let row = state.db.get_acme_order(id).await
        .map_err(|_| AcmeError::not_found())?;

    if row.account_id != account_id {
        return Err(AcmeError::unauthorized("Order does not belong to this account"));
    }

    Ok(Json(order_row_to_response(&row, &base)))
}

#[post("/order/<id>/finalize", data = "<body>")]
pub(crate) async fn finalize_order(
    state: &State<AppState>,
    body: JoseBody,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<Json<AcmeOrder>, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/order/{id}/finalize");
    let (account_id, payload_bytes) = authenticate_jws(state, &body.0, &expected_url).await?;

    let order = state.db.get_acme_order(id).await
        .map_err(|_| AcmeError::not_found())?;

    if order.account_id != account_id {
        return Err(AcmeError::unauthorized("Order does not belong to this account"));
    }

    if order.status != "ready" {
        return Err(AcmeError::malformed(format!("Order is not ready (status: {}); complete all authorizations first", order.status)));
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    if order.expires <= now_ms {
        return Err(AcmeError::malformed("Order has expired"));
    }

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AcmeError::malformed(format!("Invalid payload: {e}")))?;

    let csr_b64 = payload["csr"].as_str()
        .ok_or_else(|| AcmeError::malformed("Missing csr field"))?;
    let csr_der = base64url_decode(csr_b64)?;

    let identifiers: Vec<AcmeIdentifier> = serde_json::from_str(&order.identifiers)
        .map_err(|_| AcmeError::server_internal("Failed to parse order identifiers"))?;
    let dns_names: Vec<String> = identifiers.iter()
        .filter(|i| i.identifier_type == "dns")
        .map(|i| i.value.clone())
        .collect();

    let account = state.db.get_acme_account(account_id).await
        .map_err(|_| AcmeError::server_internal("Account lookup failed"))?;

    let ca = match account.ca_id {
        Some(ca_id) => state.db.get_ca_by_id(ca_id).await,
        None => state.db.get_latest_tls_ca().await,
    }.map_err(|_| AcmeError::server_internal("No TLS CA available"))?;

    let validity_days = ((order.not_after - now_ms) / 86_400_000).max(1) as u64;

    let cert_name = dns_names.first().map(|s| s.as_str()).unwrap_or("acme");
    let cert_common_name = Name { cn: cert_name.to_string(), ou: Some("ACME".to_string()) };
    let build_result = TLSCertificateBuilder::from_csr(&csr_der)
        .and_then(|b| b.set_name(cert_common_name.clone()))
        .and_then(|b| b.set_valid_until(validity_days, TimespanUnit::Day))
        .and_then(|b| b.set_dns_san(&dns_names))
        .and_then(|b| b.set_ca(&ca))
        .and_then(|b| b.build_server_pem());

    let (_cert_pem, chain_pem, serial) = match build_result {
        Ok(result) => result,
        Err(e) => {
            error!("Certificate issuance failed for order {id}: {e}");
            let _ = state.db.update_acme_order_status(
                id, "invalid".to_string(), None, Some(format!("Certificate issuance failed: {e}"))
            ).await;
            return Err(AcmeError::server_internal("Certificate issuance failed"));
        }
    };

    let user_id = account.user_id;

    let cert = Certificate {
        id: -1,
        name: cert_common_name,
        created_on: now_ms,
        valid_until: order.not_after,
        certificate_type: CertificateType::TLSServer,
        user_id,
        renew_method: CertificateRenewMethod::None,
        ca_id: ca.id,
        revoked_at: None,
        data: chain_pem,
        password: String::new(),
    };

    let saved_cert = state.db.insert_user_cert(cert).await
        .map_err(|_| AcmeError::server_internal("Failed to store certificate"))?;

    let _ = state.db.set_cert_acme_account(saved_cert.id, account_id).await;

    let serial_hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
    let _ = state.db.set_cert_serial(saved_cert.id, serial_hex).await;

    if state.settings.get_notify_acme_issuance() {
        let db = state.db.clone();
        let mailer = state.mailer.clone();
        let cert_clone = saved_cert.clone();
        tokio::spawn(async move {
            notify_admins_acme_issued(&db, mailer, cert_clone).await;
        });
    }

    state.db.update_acme_order_status(id, "valid".to_string(), Some(saved_cert.id), None).await
        .map_err(|_| AcmeError::server_internal("Failed to update order"))?;

    let updated_order = state.db.get_acme_order(id).await
        .map_err(|_| AcmeError::server_internal("Failed to reload order"))?;

    Ok(Json(order_row_to_response(&updated_order, &base)))
}

#[post("/authz/<authz_id>", data = "<body>")]
pub(crate) async fn get_authz(
    state: &State<AppState>,
    body: JoseBody,
    authz_id: String,
    _acme: AcmeEnabled,
) -> Result<Json<AcmeAuthorization>, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/authz/{authz_id}");
    let (account_id, _payload) = authenticate_jws(state, &body.0, &expected_url).await?;

    let (order_id, domain_idx) = parse_authz_id(&authz_id)?;

    let order = state.db.get_acme_order(order_id).await
        .map_err(|_| AcmeError::not_found())?;

    if order.account_id != account_id {
        return Err(AcmeError::unauthorized("Authorization does not belong to this account"));
    }

    let identifiers: Vec<AcmeIdentifier> = serde_json::from_str(&order.identifiers)
        .map_err(|_| AcmeError::server_internal("Failed to parse identifiers"))?;

    let identifier = identifiers.get(domain_idx)
        .ok_or_else(AcmeError::not_found)?
        .clone();

    let token = if identifier.token.is_empty() {
        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        base64url_encode(&token_bytes)
    } else {
        identifier.token.clone()
    };

    let authz_status = if identifier.status.is_empty() {
        "pending".to_string()
    } else {
        identifier.status.clone()
    };
    let challenge_status = authz_status.clone();

    let http_challenge = AcmeChallenge {
        challenge_type: "http-01".to_string(),
        url: format!("{base}/api/acme/chall/{order_id}/http-01/{domain_idx}"),
        token: token.clone(),
        status: challenge_status.clone(),
    };
    let dns_challenge = AcmeChallenge {
        challenge_type: "dns-01".to_string(),
        url: format!("{base}/api/acme/chall/{order_id}/dns-01/{domain_idx}"),
        token,
        status: challenge_status,
    };

    Ok(Json(AcmeAuthorization {
        identifier,
        status: authz_status,
        challenges: vec![http_challenge, dns_challenge],
    }))
}

#[post("/chall/<order_id>/<challenge_type>/<domain_idx>", data = "<body>")]
pub(crate) async fn get_challenge(
    state: &State<AppState>,
    body: JoseBody,
    order_id: i64,
    challenge_type: String,
    domain_idx: usize,
    _acme: AcmeEnabled,
) -> Result<Json<serde_json::Value>, AcmeError> {
    use crate::acme::jws::jwk_thumbprint;

    let base = state.settings.get_vaultls_url();
    let chall_url = format!("{base}/api/acme/chall/{order_id}/{challenge_type}/{domain_idx}");
    let (account_id, _payload) = authenticate_jws(state, &body.0, &chall_url).await?;

    if challenge_type != "http-01" && challenge_type != "dns-01" {
        return Err(AcmeError::malformed(format!("Unsupported challenge type: {challenge_type}")));
    }

    let order = state.db.get_acme_order(order_id).await
        .map_err(|_| AcmeError::not_found())?;
    if order.account_id != account_id {
        return Err(AcmeError::unauthorized("Challenge does not belong to this account"));
    }

    let identifiers: Vec<AcmeIdentifier> = serde_json::from_str(&order.identifiers)
        .map_err(|_| AcmeError::server_internal("Failed to parse identifiers"))?;

    let identifier = identifiers.get(domain_idx)
        .ok_or_else(AcmeError::not_found)?
        .clone();

    if identifier.status == "valid" {
        return Ok(Json(serde_json::json!({
            "type": challenge_type,
            "url": chall_url,
            "token": identifier.token,
            "status": "valid"
        })));
    }

    let token = identifier.token.clone();

    let account = state.db.get_acme_account(account_id).await
        .map_err(|_| AcmeError::server_internal("Account lookup failed"))?;
    let jwk_str = account.acme_jwk.ok_or_else(AcmeError::account_does_not_exist)?;
    let jwk: serde_json::Value = serde_json::from_str(&jwk_str)
        .map_err(|_| AcmeError::server_internal("Stored JWK is invalid"))?;
    let thumbprint = jwk_thumbprint(&jwk)?;
    let expected_key_auth = format!("{token}.{thumbprint}");

    let domain = &identifier.value;
    let new_status: &str = if account.auto_validate {
        "valid"
    } else if challenge_type == "dns-01" {
        let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), expected_key_auth.as_bytes())
            .map_err(|_| AcmeError::server_internal("SHA-256 computation failed"))?;
        let expected_dns_value = base64url_encode(&digest);
        let resolver_addr = state.settings.get_acme_dns_resolver();
        info!(challenge_type=challenge_type, domain=domain, resolver=resolver_addr, "Attempting ACME validation");
        if validate_dns01(domain, &expected_dns_value, &resolver_addr).await {
            "valid"
        } else {
            "invalid"
        }
    } else {
        let validation_url = format!("http://{}/.well-known/acme-challenge/{}", domain, token);
        info!(challenge_type=challenge_type, domain=domain, "Attempting ACME validation");
        let result = challenge_http_client().get(&validation_url).send().await;

        match result {
            Ok(resp) => {
                match resp.text().await {
                    Ok(body_text) if body_text.trim() == expected_key_auth => "valid",
                    Ok(_) => "invalid",
                    Err(_) => "invalid",
                }
            }
            Err(_) => "invalid",
        }
    };
    info!(challenge_type=challenge_type, domain=domain, status=new_status, "Completed ACME validation");

    state.db.update_acme_order_identifier_status(order_id, domain_idx, new_status.to_string()).await
        .map_err(|_| AcmeError::server_internal("Failed to persist challenge status"))?;

    if new_status == "valid" {
        if let Ok(refreshed) = state.db.get_acme_order(order_id).await {
            let refreshed_identifiers: Vec<AcmeIdentifier> =
                serde_json::from_str(&refreshed.identifiers).unwrap_or_default();
            if refreshed_identifiers.iter().all(|i| i.status == "valid") {
                let _ = state.db.update_acme_order_status(order_id, "ready".to_string(), None, None).await;
            }
        }
    }

    if new_status == "invalid" {
        let err_msg = format!("{challenge_type} validation failed for {domain}");
        let _ = state.db.update_acme_order_status(order_id, "invalid".to_string(), None, Some(err_msg.clone())).await;
        return Err(AcmeError::unauthorized(err_msg));
    }

    Ok(Json(serde_json::json!({
        "type": challenge_type,
        "url": chall_url,
        "token": token,
        "status": new_status
    })))
}

#[post("/cert/<id>", data = "<body>")]
pub(crate) async fn download_cert(
    state: &State<AppState>,
    body: JoseBody,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<AcmePemResponse, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/cert/{id}");
    let (account_id, _payload) = authenticate_jws(state, &body.0, &expected_url).await?;

    let cert = state.db.get_user_cert_by_id(id).await
        .map_err(|_| AcmeError::not_found())?;

    let owned = state.db.check_cert_acme_account(id, account_id).await
        .map_err(|_| AcmeError::server_internal("DB error"))?;
    if !owned {
        return Err(AcmeError::unauthorized("Certificate does not belong to this account"));
    }

    if !cert.data.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err(AcmeError::malformed("Certificate is not in PEM format"));
    }

    Ok(AcmePemResponse { body: cert.data })
}

#[post("/revoke-cert", data = "<body>")]
pub(crate) async fn revoke_cert(
    state: &State<AppState>,
    body: JoseBody,
    _acme: AcmeEnabled,
) -> Result<Status, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/revoke-cert");

    let (header, _protected_bytes, payload_bytes, signature) = parse_jws(&body.0)?;

    if header.jwk.is_some() && header.kid.is_some() {
        return Err(AcmeError::malformed("JWS protected header must not contain both jwk and kid"));
    }

    let nonce = header.nonce.as_deref().unwrap_or("");
    let valid = state.db.validate_and_delete_nonce(nonce.to_string()).await
        .map_err(|_| AcmeError::server_internal("Nonce validation failed"))?;
    if !valid {
        return Err(AcmeError::bad_nonce("Nonce is invalid or already used"));
    }

    match header.url.as_deref() {
        Some(url) if url == expected_url => {}
        Some(_) => return Err(AcmeError::unauthorized("JWS url mismatch")),
        None => return Err(AcmeError::malformed("JWS protected header missing url")),
    }

    let req: crate::acme::types::JwsRequest = serde_json::from_str(&body.0)
        .map_err(|e| AcmeError::malformed(format!("Invalid JWS: {e}")))?;

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AcmeError::malformed(format!("Invalid payload: {e}")))?;

    let cert_b64 = payload["certificate"].as_str()
        .ok_or_else(|| AcmeError::malformed("Missing certificate field"))?;
    let cert_der = base64url_decode(cert_b64)?;

    let cert_x509 = openssl::x509::X509::from_der(&cert_der)
        .map_err(|_| AcmeError::malformed("Invalid certificate DER"))?;
    let serial_bytes = cert_x509.serial_number().to_bn()
        .map_err(|_| AcmeError::server_internal("Failed to get serial"))?
        .to_vec();
    let serial_hex: String = serial_bytes.iter().map(|b| format!("{b:02x}")).collect();

    if let Some(kid) = &header.kid {
        let expected_kid_prefix = format!("{base}/api/acme/account/");
        if !kid.starts_with(&expected_kid_prefix) {
            return Err(AcmeError::malformed("Invalid kid: unexpected URL prefix"));
        }
        let account_id: i64 = kid[expected_kid_prefix.len()..]
            .parse()
            .map_err(|_| AcmeError::malformed("Invalid kid: non-numeric account id"))?;

        let account = state.db.get_acme_account(account_id).await
            .map_err(|_| AcmeError::account_does_not_exist())?;

        if account.status != "valid" {
            return Err(AcmeError::unauthorized("Account is not active"));
        }

        let jwk_str = account.acme_jwk.ok_or_else(AcmeError::account_does_not_exist)?;
        let jwk: Value = serde_json::from_str(&jwk_str)
            .map_err(|_| AcmeError::server_internal("Stored JWK is invalid"))?;

        verify_signature(&header.alg, &jwk, &req.protected, &req.payload, &signature)?;

        let cert_id = state.db.get_cert_id_by_serial_hex(serial_hex).await
            .map_err(|_| AcmeError::server_internal("DB error"))?
            .ok_or_else(AcmeError::not_found)?;

        let owned = state.db.check_cert_acme_account(cert_id, account_id).await
            .map_err(|_| AcmeError::server_internal("DB error"))?;
        if !owned {
            return Err(AcmeError::unauthorized("Certificate does not belong to this account"));
        }

        state.db.revoke_user_cert(cert_id).await
            .map_err(|_| AcmeError::server_internal("Revocation failed"))?;
        Ok(Status::Ok)

    } else if let Some(jwk) = &header.jwk {
        verify_signature(&header.alg, jwk, &req.protected, &req.payload, &signature)?;

        let cert_pubkey = cert_x509.public_key()
            .map_err(|_| AcmeError::server_internal("Failed to extract cert public key"))?;
        let cert_pubkey_der = cert_pubkey.public_key_to_der()
            .map_err(|_| AcmeError::server_internal("Failed to encode cert public key"))?;

        let jwk_pkey = jwk_to_pkey(&header.alg, jwk)?;
        let jwk_pubkey_der = jwk_pkey.public_key_to_der()
            .map_err(|_| AcmeError::server_internal("Failed to encode JWK public key"))?;

        if cert_pubkey_der != jwk_pubkey_der {
            return Err(AcmeError::unauthorized("JWK does not match certificate public key"));
        }

        let cert_id = state.db.get_cert_id_by_serial_hex(serial_hex).await
            .map_err(|_| AcmeError::server_internal("DB error"))?
            .ok_or_else(AcmeError::not_found)?;

        state.db.revoke_user_cert(cert_id).await
            .map_err(|_| AcmeError::server_internal("Revocation failed"))?;
        Ok(Status::Ok)

    } else {
        Err(AcmeError::malformed("Revocation request must include either kid or jwk"))
    }
}

#[post("/orders/<id>", data = "<body>")]
pub(crate) async fn get_account_orders(
    state: &State<AppState>,
    body: JoseBody,
    id: i64,
    _acme: AcmeEnabled,
) -> Result<Json<serde_json::Value>, AcmeError> {
    let base = state.settings.get_vaultls_url();
    let expected_url = format!("{base}/api/acme/orders/{id}");
    let (account_id, _payload) = authenticate_jws(state, &body.0, &expected_url).await?;

    if account_id != id {
        return Err(AcmeError::unauthorized("Account mismatch"));
    }

    let orders = state.db.get_orders_by_account(account_id).await
        .map_err(|_| AcmeError::server_internal("DB error"))?;

    let order_urls: Vec<String> = orders.iter()
        .map(|o| format!("{base}/api/acme/order/{}", o.id))
        .collect();

    Ok(Json(serde_json::json!({ "orders": order_urls })))
}

pub fn protocol_routes() -> Vec<rocket::Route> {
    routes![
        get_directory,
        new_nonce_head,
        new_nonce_get,
        new_account,
        new_order,
        get_order,
        get_account_orders,
        finalize_order,
        get_authz,
        get_challenge,
        download_cert,
        revoke_cert,
    ]
}
