use crate::certs::tls_cert::{get_dns_names, get_timestamp, has_email_san, renewal_validity_days, TLSCertificateBuilder};
use crate::data::enums::TimespanUnit;
use crate::data::enums::{CertificateRenewMethod, UserRole};
use crate::data::objects::User;
use crate::data::enums::CertificateType::*;
use crate::db::VaulTLSDB;
use crate::notification::mail::{MailMessage, Mailer};
use std::sync::Arc;
use std::time::Duration;
use anyhow::anyhow;
use tokio::sync::Mutex;
use tokio::time::{interval  , MissedTickBehavior};
use tracing::{debug, info, trace, warn};
use crate::certs::common::{Certificate, CA};

/// `needed_until` is a unix timestamp in ms.
fn ca_can_issue(ca: &CA, needed_until: i64) -> bool {
    ca.revoked_at.is_none() && ca.valid_until >= needed_until
}

/// The newest successor of the certificate's CA that can issue the renewed certificate is used,
/// otherwise the certificate's own CA. There is deliberately no fallback to any other CA.
fn select_renewal_ca<'a>(cas: &'a [CA], cert: &Certificate, needed_until: i64) -> Result<&'a CA, anyhow::Error> {
    let own_ca = cas.iter()
        .find(|ca| ca.id == cert.ca_id)
        .ok_or_else(|| anyhow!("The CA {} of the certificate does not exist anymore", cert.ca_id))?;

    let mut selected = ca_can_issue(own_ca, needed_until).then_some(own_ca);
    let mut current = own_ca;
    while let Some(successor) = cas.iter().find(|ca| ca.predecessor_id == Some(current.id)) {
        if ca_can_issue(successor, needed_until) {
            selected = Some(successor);
        }
        current = successor;
    }

    selected.ok_or_else(|| anyhow!("The CA {} (id {}) does not cover the validity of the renewed certificate and has no usable successor CA. Set a successor for this CA.", own_ca.name, own_ca.id))
}

/// Send a mail about a failed renewal to the owner of the certificate and all admins.
async fn notify_renewal_failed(db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>, cert: &Certificate, owner: User, reason: String) {
    let owner_id = owner.id;
    let mut recipients = vec![owner];
    if let Ok(users) = db.get_all_user().await {
        recipients.extend(users.into_iter().filter(|u| u.role == UserRole::Admin && u.id != owner_id));
    }

    let cert = cert.clone();
    tokio::spawn(async move {
        let mailer_guard = mailer_mutex.lock().await;
        let Some(mailer) = &*mailer_guard else { return };
        for user in recipients {
            let _ = mailer.notify_renewal_failed(MailMessage {
                to: format!("{} <{}>", user.name, user.email),
                username: user.name,
                certificate: cert.clone(),
            }, &reason).await;
        }
    });
}

/// Record a failed renewal. Only the first failure is logged as a warning and sent by mail.
async fn handle_renewal_failure(cert: &Certificate, db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>, reason: String) {
    if db.set_cert_renewal_failure(cert.id, reason.clone()).await.is_err() {
        return;
    }
    if cert.renewal_error.is_some() {
        debug!("Renewal of certificate {} failed again: {}", cert.name, reason);
        return;
    }

    let Ok(user) = db.get_user(cert.user_id).await else { return };
    warn!("Renewal of certificate {} owned by user {} failed: {}", cert.name, user.name, reason);
    notify_renewal_failed(db, mailer_mutex, cert, user, reason).await;
}

/// Notify all admin users that a new ACME certificate was issued.
pub(crate) async fn notify_admins_acme_issued(db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>, cert: Certificate) {
    let Ok(users) = db.get_all_user().await else { return };
    let mailer_guard = mailer_mutex.lock().await;
    let Some(mailer) = &*mailer_guard else { return };
    for user in users.into_iter().filter(|u| u.role == UserRole::Admin) {
        let _ = mailer.notify_acme_certificate_issued(MailMessage {
            to: format!("{} <{}>", user.name, user.email),
            username: user.name,
            certificate: cert.clone(),
        }).await;
    }
}

pub(crate) async fn notify_issuer_revoked(db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>, ca_id: i64) {
    let Ok(certs) = db.get_user_certs(None, Some(ca_id), Some(false)).await else { return };
    let mailer_guard = mailer_mutex.lock().await;
    let Some(mailer) = &*mailer_guard else { return };
    for cert in certs.iter().filter(|cert| matches!(cert.renew_method, CertificateRenewMethod::Notify | CertificateRenewMethod::RenewAndNotify)) {
        let Ok(user) = db.get_user(cert.user_id).await else { continue };
        info!("Notifying user {} that the CA of certificate {} was revoked.", user.name, cert.name);
        let _ = mailer.notify_issuer_revoked(MailMessage {
            to: format!("{} <{}>", user.name, user.email),
            username: user.name,
            certificate: cert.clone(),
        }).await;
    }
}

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
        check_expiring_certs(&db, mailer_mutex.clone()).await;

        ticker.tick().await;
    }
}

pub(crate) async fn check_expiring_certs(db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) {
    trace!("Checking for active certificates that are about to expire.");

    let Ok(certs) = db.get_user_certs(None, None, Some(false)).await else {
        info!("Failed to get certificates from database.");
        return;
    };
    let Ok(cas) = db.get_all_ca().await else {
        info!("Failed to get CAs from database.");
        return;
    };
    let revoked_ca_ids: Vec<i64> = cas.iter().filter(|ca| ca.revoked_at.is_some()).map(|ca| ca.id).collect();
    let in_a_week = chrono::Utc::now().timestamp_millis() + 1000 * 60 * 60 * 24 * 7;

    for cert in &certs {
        let has_renew_method = cert.renew_method != CertificateRenewMethod::None;
        let issuer_revoked = revoked_ca_ids.contains(&cert.ca_id);
        let expires_soon = cert.valid_until < in_a_week;
        if !has_renew_method || issuer_revoked || !expires_soon {
            continue;
        }

        let renews = matches!(cert.renew_method, CertificateRenewMethod::Renew | CertificateRenewMethod::RenewAndNotify);
        match handle_expiry(cert, &cas, db, mailer_mutex.clone()).await {
            Ok(()) => {
                if cert.renewal_error.is_some() {
                    info!("Renewal of certificate {} succeeded after an earlier failure.", cert.name);
                    let _ = db.clear_cert_renewal_failure(cert.id).await;
                }
                let _ = db.update_cert_renew_method(cert.id, CertificateRenewMethod::None).await;
            }
            Err(e) if renews => handle_renewal_failure(cert, db, mailer_mutex.clone(), e.to_string()).await,
            Err(e) => debug!("Handling expiry of certificate {} failed: {}", cert.name, e),
        }
    }
}

async fn handle_expiry(cert: &Certificate, cas: &[CA], db: &VaulTLSDB, mailer_mutex: Arc<Mutex<Option<Mailer>>>) -> Result<(), anyhow::Error> {
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
                    // Select the CA first so that a rejected renewal does not generate any keys.
                    let needed_until = get_timestamp(renewal_validity_days(cert) as u64, TimespanUnit::Day).unix_timestamp() * 1000;
                    let ca = select_renewal_ca(cas, cert, needed_until)?;
                    let mut cert_builder = TLSCertificateBuilder::try_from(cert)?
                        .set_ca(ca.clone())?;

                    if cert.certificate_type == TLSClient {
                        // Keep the old certificate's choice, but use the user's current email.
                        if has_email_san(cert)? {
                            cert_builder = cert_builder.set_email_san(&user.email)?;
                        }
                        cert_builder.build_client()?
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