use crate::certs::tls_cert::{get_dns_names, TLSCertificateBuilder};
use crate::data::enums::CertificateRenewMethod;
use crate::data::enums::CertificateType::*;
use crate::db::VaulTLSDB;
use crate::notification::mail::{MailMessage, Mailer};
use std::sync::Arc;
use std::time::Duration;
use anyhow::anyhow;
use tokio::sync::Mutex;
use tokio::time::{interval  , MissedTickBehavior};
use tracing::{info, trace};
use crate::certs::common::Certificate;

pub(crate) async fn watch_expiry(db: VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) {
    info!("Starting certificate expiry watcher.");
    let interval_secs = std::env::var("VAULTLS_CHECK_EXPIRY_INTERVAL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(300);

    let mut ticker = interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);


    loop {
        trace!("Checking for certificates that are about to expire.");

        if let Ok(certs) = db.get_all_user_cert(None).await {
            let in_a_week = chrono::Utc::now().timestamp_millis() + 1000 * 60 * 60 * 24 * 7;
            for cert in certs.iter().filter(|a| a.renew_method != CertificateRenewMethod::None && a.valid_until < in_a_week) {
                if handle_expiry(cert, &db, mailer_mutex.clone()).await.is_ok() {
                    let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
                }
            }
        } else {
            info!("Failed to get certificates from database.");
        }

        ticker.tick().await;
    }
}

async fn handle_expiry(cert: &Certificate, db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) -> Result<(), anyhow::Error> {
    let user = db.get_user(cert.user_id).await?;
    info!("Certificate {} owned by user {} is about to expire.", cert.name, user.name);

    match cert.renew_method {
        CertificateRenewMethod::Notify => {
            info!("Notifying user {}.", user.name);
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
            info!("Renewing certificate {} for user {}.", cert.name, user.name);

            let mut new_cert = match cert.certificate_type {
                TLSClient | TLSServer => {
                    let ca = db.get_latest_tls_ca().await?;
                    let cert_builder = TLSCertificateBuilder::try_from(cert)?
                        .set_ca(&ca)?;

                    if cert.certificate_type == TLSClient {
                        cert_builder
                            .set_email_san(&user.email)?
                            .build_client()?
                    } else {
                        let dns = get_dns_names(cert)?;
                        cert_builder
                            .set_dns_san(&dns)?
                            .build_server()?
                    }
                }
                SSHClient | SSHServer => {
                    return Err(anyhow!("SSH not supported for renewal."));
                }
            };

            new_cert = db.insert_user_cert(new_cert).await?;

            if cert.renew_method == CertificateRenewMethod::RenewAndNotify {
                info!("Notifying user {} that cert {} was renewed.", user.name, cert.name);
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