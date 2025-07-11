use std::collections::HashMap;
use anyhow::anyhow;
use crate::settings::OIDC;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims};
use openidconnect::reqwest::{ClientBuilder, Url};
use openidconnect::{reqwest, AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse};
use crate::data::enums::UserRole;
use crate::data::objects::User;

/// OIDC authentication
#[derive(Debug)]
pub(crate) struct OidcAuth {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    callback_url: RedirectUrl,
    provider: CoreProviderMetadata,
    http_client: reqwest::Client,
    oidc_state: HashMap<String, (PkceCodeVerifier, Nonce)>,
}

impl OidcAuth {
    /// Populate struct from settings
    pub(crate) async fn new(oidc_config: &OIDC) -> Result<Self, anyhow::Error> {
        let client_id = ClientId::new(oidc_config.id.clone());
        let client_secret = Some(ClientSecret::new(oidc_config.secret.clone()));
        let issuer_url = IssuerUrl::new(oidc_config.auth_url.clone())?;
        let callback_url = RedirectUrl::new(oidc_config.callback_url.clone())?;

        let http_client = ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let provider = CoreProviderMetadata::discover_async(issuer_url, &http_client).await?;
        
        Ok(OidcAuth{ client_id, client_secret, callback_url, provider, http_client, oidc_state: Default::default() })
    }

    /// Update struct when settings change
    pub(crate) async fn update_config(&mut self, oidc_config: &OIDC) -> Result<(), anyhow::Error> {
        *self = OidcAuth::new(oidc_config).await?;
        Ok(())
    }

    /// Generate OIDC authentication URL
    pub(crate) async fn generate_oidc_url(&mut self) -> Result<Url, anyhow::Error> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let client = CoreClient::from_provider_metadata(
            self.provider.clone(),
            self.client_id.clone(),
            self.client_secret.clone())
            .set_redirect_uri(self.callback_url.clone());

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        let session_id = csrf_token.secret().clone();
        self.oidc_state.insert(session_id.clone(), (pkce_verifier, nonce));

        Ok(auth_url)
    }

    /// Verify the callback code, which the client received from OIDC provider
    pub(crate) async fn verify_auth_code(&mut self, code: String, state: String) -> anyhow::Result<User> {
        if ! self.oidc_state.contains_key(&state) { return Err(anyhow!("State does not exist")) }
        let (stored_pkce, stored_nonce) = self.oidc_state.remove(&state).unwrap();

        let auth_code = AuthorizationCode::new(code.clone());

        let client = CoreClient::from_provider_metadata(
            self.provider.clone(),
            self.client_id.clone(),
            self.client_secret.clone())
            .set_redirect_uri(self.callback_url.clone());

        // Exchange the code for tokens
        let token_response = client
            .exchange_code(auth_code)?
            .set_pkce_verifier(stored_pkce)
            .request_async(&self.http_client)
            .await?;
        
        let Some(id_token) = token_response.id_token() else { return Err(anyhow!("No id token")) };

        let id_token_verifier = client.id_token_verifier();

        let claims = id_token.claims(&id_token_verifier, &stored_nonce)?;
        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg()?,
                id_token.signing_key(&id_token_verifier)?,
            )?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(anyhow!("Invalid access token"));
            }
        }

        let userinfo: CoreUserInfoClaims = client
            .user_info(token_response.access_token().clone(), None)?
            .request_async(&self.http_client)
            .await?;

        // Use claims from userinfo instead
        let oidc_id = userinfo.subject();
        let Some(user_name) = userinfo.preferred_username() else { return Err(anyhow!("No user name")) };
        let Some(user_email) = userinfo.email() else { return Err(anyhow!("No user email")) };

        Ok(User{
            id: -1,
            name: user_name.to_string(),
            email: user_email.to_string(),
            password_hash: None,
            oidc_id: Some(oidc_id.to_string()),
            role: UserRole::User
        })
    }
}
