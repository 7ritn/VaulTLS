use crate::common::constants::*;
use crate::common::helper::get_timestamp;
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
use serde_json::Value;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vaultls::cert::Certificate;
use vaultls::data::enums::{CertificateType, UserRole};
use vaultls::data::objects::User;
use x509_parser::asn1_rs::FromDer;
use x509_parser::prelude::X509Certificate;
use vaultls::data::api::IsSetupResponse;

#[tokio::test]
async fn test_version() -> Result<()>{

    let client = VaulTLSClient::new().await;

    let request = client
        .get("/server/version");
    let response = request.dispatch().await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::Plain));
    assert_eq!(response.into_string().await, Some("v0.8.0".into()));

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
    let client = VaulTLSClient::new_setup().await;
    let ca_pem = client.download_ca().await?;
    let ca_x509 = ca_pem.parse_x509()?;

    assert_eq!(ca_x509.subject.to_string(), concatcp!("CN=", TEST_CA_NAME).to_string());

    let bc = ca_x509.basic_constraints()?.expect("No basic constraints");
    assert!(bc.value.ca);

    Ok(())
}

#[tokio::test]
async fn test_login() -> Result<()>{
    let client = VaulTLSClient::new_authenticated().await;

    let user: User = client.get_current_user().await?;
    assert_eq!(user.id, 1);
    assert_eq!(user.name, TEST_USER_NAME);
    assert_eq!(user.email, TEST_USER_EMAIL);
    assert_eq!(user.role, UserRole::Admin);

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
    let now = get_timestamp(0);
    let valid_until = get_timestamp(1);

    assert_eq!(cert.id, 1);
    assert_eq!(cert.name, TEST_CLIENT_CERT_NAME);
    assert!(now > cert.created_on && cert.created_on > now - 10000 /* 10 seconds */);
    assert!(valid_until > cert.valid_until && cert.valid_until > valid_until - 10000 /* 10 seconds */);
    assert_eq!(cert.certificate_type, CertificateType::Client);
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
    assert_eq!(response.status(), Status::NotFound);
    Ok(())
}

#[tokio::test]
async fn test_server_certificate() -> Result<()> {
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
    client.create_client_cert(Some(2), Some(TEST_PASSWORD.to_string())).await?;
    client.switch_user().await?;
    let cert_der = client.download_cert_as_p12("1").await?;
    let (_, cert_x509) = X509Certificate::from_der(&cert_der)?;

    assert_eq!(cert_x509.subject.to_string(), concatcp!("CN=", TEST_CLIENT_CERT_NAME).to_string());

    let xku = cert_x509.subject_alternative_name()?.expect("No subject alternative name");
    assert_eq!(xku.value.general_names[0].to_string(), formatcp!("RFC822Name({})", TEST_SECOND_USER_EMAIL));

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
