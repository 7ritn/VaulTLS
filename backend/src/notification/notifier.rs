use crate::cert::{get_dns_names, Certificate, CertificateBuilder};
use crate::data::enums::CertificateRenewMethod;
use crate::data::enums::CertificateType::Client;
use crate::db::VaulTLSDB;
use crate::notification::mail::{MailMessage, Mailer};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::sleep;

pub(crate) async fn watch_expiry(db: VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) {
    loop {
        let Ok(certs) = db.get_all_user_cert(None).await else { continue };

        let in_a_week = chrono::Utc::now().timestamp_millis() + 1000 * 60 * 60 * 24 * 7;
        for cert in certs.iter().filter(|a| a.renew_method != CertificateRenewMethod::None && a.valid_until < in_a_week) {
            if handle_expiry(cert, &db, mailer_mutex.clone()).await.is_err() {
                let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
            }
        }

        sleep(std::time::Duration::from_secs(60)).await;
    }
}

async fn handle_expiry(cert: &Certificate, db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) -> Result<(), anyhow::Error> {
    let user = db.get_user(cert.user_id).await?;

    match cert.renew_method {
        CertificateRenewMethod::Notify => {
            let mail = MailMessage {
                to: format!("{} <{}>", user.name, user.email),
                username: user.name,
                certificate: cert.clone()
            };

            tokio::spawn(async move {
                if let Some(mailer) = &mut *mailer_mutex.lock().await {
                    let _ = mailer.notify_old_certificate(mail).await;
                }
            });
        }
        CertificateRenewMethod::Renew | CertificateRenewMethod::RenewAndNotify => {
            let ca = db.get_current_ca().await?;

            let cert_builder = CertificateBuilder::try_from(cert)?
                .set_ca(&ca)?;

            let mut new_cert = if cert.certificate_type == Client {
                cert_builder
                    .set_email_san(&user.email)?
                    .build_client()?
            } else {
                let dns = get_dns_names(cert)?;
                cert_builder
                    .set_dns_san(&dns)?
                    .build_server()?
            };

            new_cert = db.insert_user_cert(new_cert).await?;

            if cert.renew_method == CertificateRenewMethod::RenewAndNotify {
                let mail = MailMessage {
                    to: format!("{} <{}>", user.name, user.email),
                    username: user.name,
                    certificate: new_cert.clone()
                };

                tokio::spawn(async move {
                    if let Some(mailer) = &mut *mailer_mutex.lock().await {
                        let _ = mailer.notify_renewed_certificate(mail).await;
                    }
                });
            }
        }
        CertificateRenewMethod::None => {}
    }

    Ok(())
}