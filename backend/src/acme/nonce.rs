use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Request, Response};
use uuid::Uuid;
use crate::data::objects::AppState;

pub struct NonceFairing;

#[rocket::async_trait]
impl Fairing for NonceFairing {
    fn info(&self) -> Info {
        Info {
            name: "ACME Nonce Fairing",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let path = request.uri().path().as_str();
        if !path.starts_with("/api/acme/") {
            return;
        }

        let Some(state) = request.rocket().state::<AppState>() else { return };

        let nonce = Uuid::new_v4().to_string();

        let _ = state.db.insert_acme_nonce(nonce.clone()).await;

        response.set_raw_header("Replay-Nonce", nonce);
        response.set_raw_header("Cache-Control", "no-store");

        let _ = state.db.cleanup_old_nonces().await;
        let _ = state.db.cleanup_expired_orders().await;
    }
}

pub async fn generate_nonce(db: &crate::db::VaulTLSDB) -> Result<String, super::types::AcmeError> {
    let nonce = Uuid::new_v4().to_string();
    db.insert_acme_nonce(nonce.clone()).await
        .map_err(|_| super::types::AcmeError::server_internal("Failed to generate nonce"))?;

    let _ = db.cleanup_old_nonces().await;

    Ok(nonce)
}
