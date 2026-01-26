use crate::common::constants::*;
use crate::common::helper::{extract_ssh_cert_key_bundle, get_timestamp_ms, get_timestamp_s};
use crate::common::test_client::VaulTLSClient;
use anyhow::Result;
use const_format::{concatcp, formatcp};
use openssl::pkcs12::Pkcs12;
use openssl::x509::X509;
use rocket::http::{ContentType, Status};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;
use std::time::Duration;
use argon2::password_hash::SaltString;
use argon2::PasswordHasher;
use serde_json::Value;
use ssh_key::certificate::CertType;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vaultls::data::enums::{CAType, CertificateRenewMethod, CertificateType, TimespanUnit, UserRole};
use vaultls::data::objects::User;
use x509_parser::asn1_rs::FromDer;
use x509_parser::prelude::X509Certificate;
use vaultls::certs::common::{Certificate, CA};
use vaultls::constants::ARGON2;
use vaultls::data::api::{CreateUserCertificateRequest, IsSetupResponse, SetupRequest};

#[tokio::test]
async fn test_version() -> Result<()>{

    let client = VaulTLSClient::new().await;

    let request = client
        .get("/server/version");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::Plain));
    assert_eq!(response.into_string().await, Some("v0.10.0".into()));

    Ok(())
}

#[tokio::test]
async fn test_is_setup() -> Result<()> {
    let client = VaulTLSClient::new_setup().await;

    let request = client
        .get("/server/setup");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let is_setup: IsSetupResponse = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert!(is_setup.setup);
    assert!(is_setup.password);
    assert_eq!(is_setup.oidc, String::new());

    Ok(())
}

#[tokio::test]
async fn test_ca_download() -> Result<()>{
    let client = VaulTLSClient::new_authenticated().await;

    let old_cas: Vec<CA> = client.get_all_ca().await?;
    assert_eq!(old_cas.len(), 1);

    let ca_by_id_pem = client.download_tls_ca_by_id(1).await?;
    let ca_pem = client.download_current_tls_ca().await?;
    assert_eq!(ca_pem, ca_by_id_pem);
    let ca_x509 = ca_pem.parse_x509()?;

    assert_eq!(ca_x509.subject.to_string(), concatcp!("CN=", TEST_CA_NAME).to_string());

    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    Ok(())
}

#[tokio::test]
async fn test_login() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let user: User = client.get_current_user().await?;
    assert_eq!(user.id, 1);
    assert_eq!(user.name, TEST_USER_NAME);
    assert_eq!(user.email, TEST_USER_EMAIL);
    assert_eq!(user.role, UserRole::Admin);

    Ok(())
}

#[tokio::test]
async fn test_setup_hash() -> Result<()> {
    let client = VaulTLSClient::new().await;

    let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS".to_owned();
    let salt = SaltString::encode_b64(salt_str.as_bytes()).unwrap();
    let password_hash = ARGON2.hash_password(TEST_PASSWORD.as_bytes(), &salt).expect("hash_password");

    let setup_data = SetupRequest{
        name: TEST_USER_NAME.to_string(),
        email: TEST_USER_EMAIL.to_string(),
        ca_name: TEST_CA_NAME.to_string(),
        validity_duration: Some(1),
        validity_unit: Some(TimespanUnit::Year),
        password: Some(password_hash.to_string()),
    };

    let request = client
        .post("/server/setup")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&setup_data)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    drop(response);

    client.login(TEST_USER_EMAIL, &password_hash.to_string()).await?;

    Ok(())

}

#[tokio::test]
async fn test_login_hash() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.logout().await?;

    let salt_str = "VaulTLSVaulTLSVaulTLSVaulTLS".to_owned();
    let salt = SaltString::encode_b64(salt_str.as_bytes()).unwrap();
    let password_hash = ARGON2.hash_password(TEST_PASSWORD.as_bytes(), &salt).expect("hash_password");

    client.login(TEST_USER_EMAIL, &password_hash.to_string()).await
}

#[tokio::test]
async fn test_create_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let cert = client.create_client_cert(None, None, None).await?;

    let now = get_timestamp_ms(0);
    let valid_until = get_timestamp_ms(1);

    assert_eq!(cert.id, 1);
    assert_eq!(cert.name, TEST_CLIENT_CERT_NAME);
    assert!(now > cert.created_on && cert.created_on > now - 10000 /* 10 seconds */);
    assert!(valid_until > cert.valid_until && cert.valid_until > valid_until - 10000 /* 10 seconds */);
    assert_eq!(cert.certificate_type, CertificateType::TLSClient);
    assert_eq!(cert.user_id, 1);
    assert_eq!(cert.renew_method , CertificateRenewMethod::Renew);
    assert_eq!(cert.ca_id, 1);
    Ok(())
}

#[tokio::test]
async fn test_fetch_client_certificates() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let request = client
        .get("/certificates");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let certs: Vec<Certificate> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];
    let now = get_timestamp_ms(0);
    let valid_until = get_timestamp_ms(1);

    assert_eq!(cert.id, 1);
    assert_eq!(cert.name, TEST_CLIENT_CERT_NAME);
    assert!(now > cert.created_on && cert.created_on > now - 10000 /* 10 seconds */);
    assert!(valid_until > cert.valid_until && cert.valid_until > valid_until - 10000 /* 10 seconds */);
    assert_eq!(cert.certificate_type, CertificateType::TLSClient);
    assert_eq!(cert.user_id, 1);


    Ok(())
}

#[tokio::test]
async fn test_download_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;
    assert_eq!(cert_x509.subject.to_string(), concatcp!("CN=", TEST_CLIENT_CERT_NAME).to_string());

    let xku = cert_x509.extended_key_usage()?.expect("No extended key usage");
    assert!(xku.value.client_auth);

    Ok(())
}

#[tokio::test]
async fn test_fetch_password_for_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let request = client
        .get("/certificates/1/password");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let password: String = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(password, TEST_PASSWORD);

    Ok(())
}

#[tokio::test]
async fn test_delete_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;

    let request = client
        .delete("/certificates/1");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);

    let request = client
        .get("/certificates/1/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);
    Ok(())
}

#[tokio::test]
async fn test_create_server_certificate() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_server_cert().await?;

    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;
    assert_eq!(cert_x509.subject.to_string(), concatcp!("CN=", TEST_SERVER_CERT_NAME).to_string());

    let xku = cert_x509.extended_key_usage()?.expect("No extended key usage");
    assert!(xku.value.server_auth);

    Ok(())
}

#[tokio::test]
async fn test_tls_connection() -> Result<()> {
    let client = VaulTLSClient::new_with_cert().await;
    client.create_server_cert().await?;

    let request = client
        .get("/certificates/ca/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(ref ca_cert_pem) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };

    let request = client
        .get("/certificates/1/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(ref client_cert_p12) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };

    let request = client
        .get("/certificates/2/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(ref server_cert_p12) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };

    establish_tls_connection(ca_cert_pem, client_cert_p12, server_cert_p12).await?;

    Ok(())
}

#[tokio::test]
async fn test_create_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_user().await?;

    let request = client
        .get("/users");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));

    let users: Vec<User> = serde_json::from_str(&response.into_string().await.unwrap())?;
    assert_eq!(users.len(), 2);

    client.switch_user().await?;

    let user: User = client.get_current_user().await?;
    assert_eq!(user.id, 2);
    assert_eq!(user.name, TEST_SECOND_USER_NAME);
    assert_eq!(user.email, TEST_SECOND_USER_EMAIL);
    assert_eq!(user.role, UserRole::User);

    Ok(())
}

#[tokio::test]
async fn test_update_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let mut user = client.get_current_user().await?;

    assert_eq!(user.email, TEST_USER_EMAIL);

    user.email = TEST_SECOND_USER_EMAIL.to_string();

    let request = client
        .put("/users/1")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user)?);
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    user = client.get_current_user().await?;
    assert_eq!(user.email, TEST_SECOND_USER_EMAIL);

    Ok(())
}

#[tokio::test]
async fn test_delete_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_user().await?;

    let request = client
        .delete("/users/2");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);

    Ok(())
}

#[tokio::test]
async fn test_create_cert_for_second_user() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_user().await?;
    client.create_client_cert(Some(2), Some(TEST_PASSWORD.to_string()), None).await?;
    client.switch_user().await?;
    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;

    assert_eq!(cert_x509.subject.to_string(), concatcp!("CN=", TEST_CLIENT_CERT_NAME).to_string());

    let xku = cert_x509.subject_alternative_name()?.expect("No subject alternative name");
    assert_eq!(xku.value.general_names[0].to_string(), formatcp!("RFC822Name({})", TEST_SECOND_USER_EMAIL));

    Ok(())
}

#[tokio::test]
async fn test_create_new_ca() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_second_ca().await?;
    let new_cas: Vec<CA> = client.get_all_ca().await?;

    let now = get_timestamp_ms(0);
    let valid_until = get_timestamp_ms(15);

    assert_eq!(new_cas.len(), 2);
    assert_eq!(new_cas[1].name, TEST_SECOND_CA_NAME.to_string());
    assert_eq!(new_cas[1].id, 2);
    assert!(now >= new_cas[1].created_on && new_cas[1].created_on > now - 10000 /* 10 seconds */);
    assert!(valid_until >= new_cas[1].valid_until && new_cas[1].valid_until > valid_until - 10000 /* 10 seconds */);

    let ca_by_id_pem = client.download_tls_ca_by_id(2).await?;
    let ca_pem = client.download_current_tls_ca().await?;
    assert_eq!(ca_pem, ca_by_id_pem);
    let ca_x509 = ca_pem.parse_x509()?;

    assert_eq!(ca_x509.subject.to_string(), concatcp!("CN=", TEST_SECOND_CA_NAME).to_string());

    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    let old_ca = client.download_tls_ca_by_id(1).await?;
    let old_ca_x509 = old_ca.parse_x509()?;
    assert_eq!(old_ca_x509.subject.to_string(), concatcp!("CN=", TEST_CA_NAME).to_string());

    Ok(())
}

#[tokio::test]
async fn test_create_certificate_with_second_ca() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_second_ca().await?;
    let certificate = client.create_client_cert(None, None, None).await?;
    assert_eq!(certificate.ca_id, 2);

    let certificate = client.create_client_cert(None, None, Some(1)).await?;
    assert_eq!(certificate.ca_id, 1);

    Ok(())
}

#[tokio::test]
async fn test_create_certificate_with_short_lived_ca() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;

    let cert_req = CreateUserCertificateRequest {
        cert_name: TEST_CLIENT_CERT_NAME.to_string(),
        validity_duration: Some(2),
        validity_unit: Some(TimespanUnit::Year),
        user_id: 1,
        notify_user: None,
        system_generated_password: false,
        cert_password: None,
        cert_type: Some(CertificateType::TLSClient),
        usage_limit: None,
        renew_method: Some(CertificateRenewMethod::Renew),
        ca_id: None,
    };

    let request = client
        .post("/certificates")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&cert_req)?);
    let response = request.dispatch().await;

    let certificate: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;

    assert_eq!(certificate.ca_id, 2);

    Ok(())
}

#[tokio::test]
async fn test_settings() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    let mut settings = client.get_settings().await?;
    assert_eq!(settings["common"]["password_rule"], 0);

    settings["common"]["password_rule"] = Value::Number(2.into());

    client.put_settings(settings).await?;

    settings = client.get_settings().await?;
    assert_eq!(settings["common"]["password_rule"], 2);

    Ok(())
}

#[tokio::test]
async fn test_create_ssh_ca() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_ssh_ca().await?;
    client.download_current_ssh_ca().await?;
    let cas = client.get_all_ca().await?;
    let ca = cas.get(1).unwrap();

    let now = get_timestamp_ms(0);

    assert_eq!(ca.id, 2);
    assert_eq!(ca.name, TEST_SSH_CA_NAME);
    assert!(now > ca.created_on && ca.created_on > now - 10000 /* 10 seconds */);
    assert_eq!(ca.ca_type, CAType::SSH);
    Ok(())
}

#[tokio::test]
async fn test_create_ssh_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_ssh_ca().await?;
    let cert = client.create_ssh_client_cert().await?;

    let now = get_timestamp_ms(0);
    let valid_until = get_timestamp_ms(1);

    assert_eq!(cert.id, 1);
    assert_eq!(cert.name, TEST_SSH_CLIENT_CERT_NAME);
    assert!(now > cert.created_on && cert.created_on > now - 10000 /* 10 seconds */);
    assert!(valid_until > cert.valid_until && cert.valid_until > valid_until - 10000 /* 10 seconds */);
    assert_eq!(cert.certificate_type, CertificateType::SSHClient);
    assert_eq!(cert.user_id, 1);
    assert_eq!(cert.renew_method , CertificateRenewMethod::Notify);
    assert_eq!(cert.ca_id, 2);
    Ok(())
}

#[tokio::test]
async fn test_download_ssh_client_certificate() -> Result<()> {
    let client = VaulTLSClient::new_authenticated().await;
    client.create_ssh_ca().await?;
    let _ = client.create_ssh_client_cert().await?;

    // Download SSH public CA key
    let request = client.get("/certificates/ca/ssh/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(ca_data) = response.into_bytes().await else {
        return Err(anyhow::anyhow!("No SSH CA public key"))
    };

    // Download SSH client certificate
    let request = client.get("/certificates/1/download");
    let response = request.dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let Some(client_data) = response.into_bytes().await else {
        return Err(anyhow::anyhow!("No SSH client certificate"))
    };

    let ca_str = String::from_utf8(ca_data)?;
    let ca = ssh_key::PublicKey::from_openssh(&ca_str)?;

    let (cert, _) = extract_ssh_cert_key_bundle(&client_data)?;

    assert_eq!(cert.cert_type(), CertType::User);

    let now: u64 = get_timestamp_s(0) as u64;
    let valid_until: u64 = get_timestamp_s(1) as u64;
    assert!(now >= cert.valid_after() && cert.valid_after() >= now - 10 /* 10 seconds */);
    assert!(valid_until >= cert.valid_before() && cert.valid_before() >= valid_until - 10 /* 10 seconds */);

    assert_eq!(cert.valid_principals(), vec!["test.example.com".to_string()]);
    let fingerprint = ca.fingerprint(Default::default());
    assert!(cert.validate(vec![&fingerprint]).is_ok());

    Ok(())
}

async fn establish_tls_connection(
    ca_cert_pem: &[u8],
    client_cert_p12: &[u8],
    server_cert_p12: &[u8],
) -> Result<()> {
    let crypto = rustls::crypto::aws_lc_rs::default_provider();
    crypto.install_default().expect("TODO: panic message");

    // Parse the CA certificate
    let ca_x509 = X509::from_pem(ca_cert_pem)?;

    // Create root cert store
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(CertificateDer::from(ca_x509.to_der()?))?;
    let verifier = WebPkiClientVerifier::builder(root_store.clone().into()).allow_unauthenticated().build().expect("failed to build client verifier");

    // Parse client certificate and private key from PKCS12
    let client_p12 = Pkcs12::from_der(client_cert_p12)?;
    let client_p12_parsed = client_p12.parse2(TEST_PASSWORD)?;
    let client_cert_der = client_p12_parsed.cert.unwrap().to_der()?;
    let client_key_pem = client_p12_parsed.pkey.unwrap().private_key_to_pem_pkcs8()?;

    // Parse server certificate and private key from PKCS12
    let server_p12 = Pkcs12::from_der(server_cert_p12)?;
    let server_p12_parsed = server_p12.parse2(TEST_PASSWORD)?;
    let server_cert_der = server_p12_parsed.cert.unwrap().to_der()?;
    let server_key_pem = server_p12_parsed.pkey.unwrap().private_key_to_pem_pkcs8()?;

    // Configure Server
    let server_config = Arc::new(ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(server_cert_der)], PrivateKeyDer::from_pem_slice(&server_key_pem)?)?);

    // Configure Client
    let client_config = Arc::new(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(vec![CertificateDer::from(client_cert_der)], PrivateKeyDer::from_pem_slice(&client_key_pem)?)?);

    let (client_stream, server_stream) = duplex(1024);

    let acceptor = TlsAcceptor::from(server_config);
    let connector = TlsConnector::from(client_config);

    let server_task = tokio::spawn(async move {
        let mut received = String::new();
        let mut stream = acceptor.accept(server_stream).await.unwrap();
        stream.read_to_string(&mut received).await.unwrap();
        assert_eq!(received, TEST_MESSAGE);
    });

    let mut stream = connector.connect("localhost".try_into()?, client_stream).await?;
    stream.write_all(TEST_MESSAGE.as_ref()).await?;
    stream.flush().await?;
    sleep(Duration::from_millis(1)).await;
    stream.shutdown().await?;
    server_task.await?;

    Ok(())
}
