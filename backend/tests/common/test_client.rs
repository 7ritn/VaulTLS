use crate::common::constants::*;
use anyhow::Result;
use openssl::pkcs12::Pkcs12;
use rocket::http::{ContentType, Status};
use rocket::local::asynchronous::Client;
use std::ops::{Deref, DerefMut};
use serde_json::Value;
use vaultls::create_test_rocket;
use vaultls::data::api::{CreateCARequest, CreateUserCertificateRequest, CreateUserRequest, LoginRequest, SetupRequest};
use vaultls::data::enums::{CAType, CertificateRenewMethod, CertificateType, TimespanUnit, UserRole};
use x509_parser::pem::Pem;
use vaultls::certs::common::{Certificate, CA};
use vaultls::data::enums::CertificateType::{SSHClient, TLSClient};
use vaultls::data::objects::User;

pub(crate) struct VaulTLSClient(Client);

impl Deref for VaulTLSClient {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for VaulTLSClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl VaulTLSClient {
    pub(crate) async fn new() -> Self {
        let rocket_build = create_test_rocket().await;
        let rocket = rocket_build.ignite().await.unwrap();
        VaulTLSClient(Client::tracked(rocket)
            .await
            .unwrap()
        )
    }

    pub(crate) async fn new_setup() -> Self {
        let client = Self::new().await;

        let setup_data = SetupRequest{
            name: TEST_USER_NAME.to_string(),
            email: TEST_USER_EMAIL.to_string(),
            ca_name: TEST_CA_NAME.to_string(),
            validity_duration: Some(2),
            validity_unit: Some(TimespanUnit::Year),
            password: Some(TEST_PASSWORD.to_string()),
        };

        let request = client
            .post("/server/setup")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&setup_data).unwrap());
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        drop(response);

        client
    }

    pub(crate) async fn new_authenticated() -> Self {
        let client = Self::new_setup().await;
        client.login(TEST_USER_EMAIL, TEST_PASSWORD).await.unwrap();
        client
    }

    pub(crate) async fn new_with_cert() -> Self {
        let client = Self::new_authenticated().await;
        client.create_client_cert(None, Some(TEST_PASSWORD.to_string()), None).await.unwrap();
        client
    }

    pub(crate) async fn new_authenticated_unprivileged() -> Self {
        let client = Self::new_authenticated().await;
        client.create_user().await.unwrap();
        client.switch_user().await.unwrap();
        client
    }

    pub(crate) async fn create_client_cert(&self, user_id: Option<i64>, password: Option<String>, ca_id: Option<i64>) -> Result<Certificate> {
        let cert_req = CreateUserCertificateRequest {
            cert_name: TEST_CLIENT_CERT_NAME.into(),
            validity_duration: Some(1),
            validity_unit: Some(TimespanUnit::Year),
            user_id: user_id.unwrap_or(1),
            notify_user: None,
            system_generated_password: false,
            cert_password: password,
            cert_type: Some(TLSClient),
            usage_limit: None,
            renew_method: Some(CertificateRenewMethod::Renew),
            ca_id,
        };

        let request = self
            .post("/certificates")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn create_ssh_client_cert(&self) -> Result<Certificate> {
        let cert_req = CreateUserCertificateRequest {
            cert_name: TEST_SSH_CLIENT_CERT_NAME.to_string().into(),
            validity_duration: Some(1),
            validity_unit: Some(TimespanUnit::Year),
            user_id: 1,
            notify_user: None,
            system_generated_password: false,
            cert_password: Some(TEST_PASSWORD.to_string()),
            cert_type: Some(SSHClient),
            usage_limit: Some(vec!["test.example.com".to_string()]),
            renew_method: Some(CertificateRenewMethod::Notify),
            ca_id: None,
        };

        let request = self
            .post("/certificates")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn create_server_cert(&self) -> Result<()> {
        let cert_req = CreateUserCertificateRequest {
            cert_name: TEST_SERVER_CERT_NAME.to_string().into(),
            validity_duration: Some(1),
            validity_unit: Some(TimespanUnit::Year),
            user_id: 1,
            notify_user: None,
            system_generated_password: false,
            cert_password: Some(TEST_PASSWORD.to_string()),
            cert_type: Some(CertificateType::TLSServer),
            usage_limit: Some(vec![TEST_SERVER_CERT_DNS_NAME.to_string()]),
            renew_method: None,
            ca_id: None,
        };

        let request = self
            .post("/certificates")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&cert_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        let cert: Certificate = serde_json::from_str(&response.into_string().await.unwrap())?;

        assert_eq!(cert.certificate_type, CertificateType::TLSServer);
        Ok(())
    }

    pub(crate) async fn create_user(&self) -> Result<()> {
        let user_req = CreateUserRequest {
            user_name: TEST_SECOND_USER_NAME.to_string(),
            user_email: TEST_SECOND_USER_EMAIL.to_string(),
            password: Some(TEST_PASSWORD.to_string()),
            role: UserRole::User,
        };

        let request = self
            .post("/users")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&user_req)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }

    pub(crate) async fn get_current_user(&self) -> Result<User> {
        let request = self
            .get("/auth/me");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn switch_user(&self) -> Result<()> {
        self.logout().await?;
        self.login(TEST_SECOND_USER_EMAIL, TEST_PASSWORD).await?;

        Ok(())
    }

    pub(crate) async fn login(&self, user_email: &str, user_password: &str) -> Result<()> {
        let login_data = LoginRequest{
            email: user_email.to_string(),
            password: user_password.to_string()
        };

        let request = self
            .post("/auth/login")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&login_data)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }
    
    pub(crate) async fn logout(&self) -> Result<()> {
        let request = self
            .post("/auth/logout");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }

    pub(crate) async fn download_cert(&self, cert_id: &str) -> Result<Vec<u8>> {
        let request = self
            .get(format!("/certificates/{cert_id}/download"));
        let response = request.dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::Text));

        let Some(body) = response.into_bytes().await else { return Err(anyhow::anyhow!("No body")) };
        assert!(!body.is_empty());

        Ok(body)
    }

    pub(crate) async fn download_cert_as_p12(&self, cert_id: &str) -> Result<Vec<u8>> {
        let p12_der = self.download_cert(cert_id).await?;
        let p12 = Pkcs12::from_der(&p12_der)?;
        let parsed_p12 = p12.parse2(TEST_PASSWORD)?;
        let cert = parsed_p12.cert.expect("No certificate found");
        Ok(cert.to_der()?)
    }

    pub(crate) async fn download_current_tls_ca(&self) -> Result<Pem> {
        let x509_pem = self.download_cert("ca").await?;
        Ok(Pem::iter_from_buffer(&x509_pem)
            .nth(0)
            .expect("No PEM block found")?)
    }

    pub(crate) async fn download_current_ssh_ca(&self) -> Result<Vec<u8>> {
        Ok(self.download_cert("ca/ssh").await?)
    }

    pub(crate) async fn download_tls_ca_by_id(&self, id: i64) -> Result<Pem> {
        let x509_pem = self.download_cert(&format!("ca/{}", id)).await?;
        Ok(Pem::iter_from_buffer(&x509_pem)
            .nth(0)
            .expect("No PEM block found")?)
    }

    pub(crate) async fn get_settings(&self) -> Result<Value> {
        let request = self
            .get("/settings");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn put_settings(&self, settings: Value) -> Result<()> {
        let request = self
            .put("/settings")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&settings)?);
        let response = request.dispatch().await;

        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }

    pub(crate) async fn get_all_ca(&self) -> Result<Vec<CA>> {
        let request = self
            .get("/certificates/ca");
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::JSON));

        Ok(serde_json::from_str(&response.into_string().await.unwrap())?)
    }

    pub(crate) async fn create_second_ca(&self) -> Result<()> {
        let data = CreateCARequest {
            ca_name: TEST_SECOND_CA_NAME.to_string().into(),
            ca_type: CAType::TLS,
            validity_duration: Some(15),
            validity_unit: Some(TimespanUnit::Year),
        };

        let request = self
            .post("/certificates/ca")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&data)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }

    pub(crate) async fn create_ssh_ca(&self) -> Result<()> {
        let data = CreateCARequest {
            ca_name: TEST_SSH_CA_NAME.to_string().into(),
            ca_type: CAType::SSH,
            validity_duration: None,
            validity_unit: None,
        };

        let request = self
            .post("/certificates/ca")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&data)?);
        let response = request.dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        Ok(())
    }
}