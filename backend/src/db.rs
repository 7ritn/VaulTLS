use crate::constants::{DB_FILE_PATH, TEMP_DB_FILE_PATH};
use crate::data::enums::{CAType, CertificateRenewMethod, UserRole};
use crate::data::objects::User;
use crate::helper::get_secret;
use anyhow::anyhow;
use anyhow::Result;
use include_dir::{include_dir, Dir};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{params, Connection};
use rusqlite_migration::Migrations;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use const_format::formatcp;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tracing::{debug, info, trace, warn};
use crate::acme::types::{AcmeAccount, AcmeIdentifier, AdminAcmeOrder, AcmeOrderRow};
use crate::auth::password_auth::Password;
use crate::certs::common::{Certificate, CA};

static MIGRATIONS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/migrations");

macro_rules! db_do {
    ($pool:expr, $operation:expr) => {
        {
            let pool = $pool.clone();
            tokio::task::spawn_blocking(move || {
                let conn = pool.get().map_err(|e| {
                    anyhow!("DB pool error: {}", e)
                })?;
                $operation(&conn)
            }).await?
        }
    };
}


#[derive(Debug, Clone)]
pub(crate) struct VaulTLSDB {
    pool: Pool<SqliteConnectionManager>,
}

impl VaulTLSDB {
    pub(crate) fn new(db_encrypted: bool, mem: bool) -> Result<Self> {
        // The next two lines are for backward compatability and should be removed in a future release
        let db_initialized = if !mem {
            let db_path = Path::new(DB_FILE_PATH);
            db_path.exists()
        } else {
            false
        };

        let mut manager = if !mem {
            SqliteConnectionManager::file(DB_FILE_PATH)
        } else {
            debug!("Opening in-memory database");
            SqliteConnectionManager::memory()
        };

        let db_secret_result = get_secret("VAULTLS_DB_SECRET");
        manager = if db_encrypted {
            debug!("Using encrypted database");
            if let Ok(ref db_secret_result) = db_secret_result {
                let db_secret = db_secret_result.clone();
                manager.with_init(move |conn| {
                    conn.pragma_update(None, "key", db_secret.clone())?;
                    conn.pragma_update(None, "foreign_keys", "ON")?;
                    Ok(())
                })
            } else {
                return Err(anyhow!("VAULTLS_DB_SECRET missing".to_string()));
            }
        } else {
            manager.with_init(|connection| {
                connection.pragma_update(None, "foreign_keys", "ON")?;
                Ok(())
            })
        };

        let pool = Pool::builder()
            .max_size(1)
            .build(manager)?;
        let mut connection = pool.get()?;

        // This if statement can be removed in a future version
        if db_initialized {
            debug!("Correcting user_version of database");
            let user_version: i32 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .expect("Failed to get PRAGMA user_version");
            // Database already initialized, update user_version to 1
            if user_version == 0 {
                connection.pragma_update(None, "user_version", "1")?;
            }
        }

        Self::migrate_database(&mut connection)?;

        Ok(Self { pool })
    }

    pub(crate) fn migrate_to_encrypted(db_secret: &str) -> Result<()> {
        let connection = Connection::open(DB_FILE_PATH)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;

        Self::create_encrypt_db(&connection, db_secret)?;
        drop(connection);
        Self::migrate_to_encrypted_db()?;
        info!("Migrated to encrypted database");
        Ok(())
    }

    /// Create a new encrypted database with cloned data
    fn create_encrypt_db(conn: &Connection, new_db_secret: &str) -> Result<()> {
        let encrypted_path = TEMP_DB_FILE_PATH;
        conn.execute(
            "ATTACH DATABASE ?1 AS encrypted KEY ?2",
            params![encrypted_path, new_db_secret],
        )?;

        // Migrate data
        conn.query_row("SELECT sqlcipher_export('encrypted');", [], |_row| Ok(()))?;
        // Copy user_version for migrations
        let user_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        conn.pragma_update(Some("encrypted"), "user_version", user_version.to_string())?;

        conn.execute("DETACH DATABASE encrypted;", [])?;
        Ok(())
    }

    /// Migrate the unencrypted database to an encrypted database
    fn migrate_to_encrypted_db() -> Result<()> {
        fs::remove_file(DB_FILE_PATH)?;
        fs::rename(TEMP_DB_FILE_PATH, DB_FILE_PATH)?;
        Ok(())
    }

    fn migrate_database(conn: &mut Connection) -> Result<()> {
        let migrations = Migrations::from_directory(&MIGRATIONS_DIR).expect("Failed to load migrations");
        migrations.to_latest(conn).expect("Failed to migrate database");
        debug!("Database migrated to latest version");

        Ok(())
    }

    pub(crate) async fn fix_password(&self) -> Result<()> {
        let users = self.get_all_user().await?;

        trace!("Checking for users with empty passwords");

        for id in users.iter().map(|user| user.id) {
            let user = self.get_user(id).await?;
            if let Some(stored_password) = user.password_hash && stored_password.verify("") {
                // Password stored is empty
                info!("Password for user {} is empty, disabling password", user.name);
                self.unset_user_password(user.id).await?;
            }
        }
        Ok(())
    }

    /// Insert a new CA certificate into the database
    /// Adds id to the Certificate struct
    pub(crate) async fn insert_ca(
        &self,
        mut ca: CA
    ) -> Result<CA> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO ca_certificates (name, created_on, valid_until, type, certificate, key, crl_number) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![ca.name, ca.created_on, ca.valid_until, ca.ca_type as u8, ca.cert, ca.key, ca.crl_number],
            )?;
            ca.id = conn.last_insert_rowid();
            Ok(ca)
        })
    }

    /// Delete a CA from the database
    pub(crate) async fn delete_ca(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM ca_certificates WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    pub(crate) async fn get_latest_tls_ca(&self) -> Result<CA> {
        let query = formatcp!("SELECT id, name, created_on, valid_until, type, certificate, key, crl_number FROM ca_certificates WHERE type = {} ORDER BY id DESC LIMIT 1", CAType::TLS as u8);
        self.get_ca_by_query(query.to_string(), None).await
    }

    pub(crate) async fn get_latest_ssh_ca(&self) -> Result<CA> {
        let query = formatcp!("SELECT id, name, created_on, valid_until, type, certificate, key, crl_number FROM ca_certificates WHERE type = {} ORDER BY id DESC LIMIT 1", CAType::SSH as u8);
        self.get_ca_by_query(query.to_string(), None).await
    }

    pub(crate) async fn get_ca_by_id(&self, ca_id: i64) -> Result<CA> {
        let query = "SELECT id, name, created_on, valid_until, type, certificate, key, crl_number FROM ca_certificates WHERE id = ?1";
        self.get_ca_by_query(query.to_string(), Some(ca_id)).await
    }

    /// Retrieve a CA entry from the database. If no ID is specified, the most recent is returned.
    async fn get_ca_by_query(&self, query: String, ca_id: Option<i64>) -> Result<CA> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(&query)?;
            let mut rows = match ca_id {
                None => stmt.query([])?,
                Some(ca_id) => stmt.query(params![ca_id])?
            };

            let row = rows.next()?.ok_or_else(|| anyhow!("No CA found"))?;
            Ok(CA {
                id: row.get(0)?,
                name: row.get(1).unwrap_or_default(),
                created_on: row.get(2)?,
                valid_until: row.get(3)?,
                ca_type: row.get(4)?,
                cert: row.get(5)?,
                key: row.get(6)?,
                crl_number: row.get(7)?,
            })
        })
    }

    /// Retrieve all CA certificates from the database
    pub(crate) async fn get_all_ca(&self) -> Result<Vec<CA>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, name, created_on, valid_until, type, certificate, key, crl_number FROM ca_certificates ORDER BY id ASC")?;
            let query = stmt.query([])?;
            Ok(query.map(|row| {
                Ok(CA{
                    id: row.get(0)?,
                    name: row.get(1).unwrap_or_default(),
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    ca_type: row.get(4)?,
                    cert: row.get(5)?,
                    key: row.get(6)?,
                    crl_number: row.get(7)?,
                })
            })
            .collect()?)
        })
    }

    /// Count user certificates that have a specific CA ID
    pub(crate) async fn count_user_certs_by_ca_id(&self, ca_id: i64) -> Result<i64> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE ca_id = ?1",
                params![ca_id],
                |row| row.get(0)
            )?)
        })
    }

    pub(crate) async fn increase_ca_crl_number(&self, ca_id: i64, crl_number: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE ca_certificates SET crl_number = ?1 WHERE id=?2",
                params![crl_number, ca_id]
            ).map(|_| ())?)
        })
    }


    /// Retrieve user certificates from the database
    /// If user_id is Some, only certificates for that user are returned
    /// If ca_id is Some, only certificates signed by that CA are returned
    /// If filter_revoked is Some, only certificates that are (not) revoked are returned
    pub(crate) async fn get_user_certs(&self, user_id: Option<i64>, ca_id: Option<i64>, filter_revoked: Option<bool>) -> Result<Vec<Certificate>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut query = String::from("SELECT id, name, created_on, valid_until, data, password, user_id, type, renew_method, ca_id, revoked_at FROM user_certificates WHERE 1=1");
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(id) = user_id {
                query.push_str(" AND user_id = ?");
                params.push(Box::new(id));
            }

            if let Some(id) = ca_id {
                query.push_str(" AND ca_id = ?");
                params.push(Box::new(id));
            }

            if let Some(revoked) = filter_revoked {
                let query_str = match revoked {
                    true => " AND revoked_at IS NOT NULL",
                    false => " AND revoked_at IS NULL"
                };
                query.push_str(query_str);
            }

            let mut stmt = conn.prepare(&query)?;
            let rows = stmt.query(rusqlite::params_from_iter(params))?;

            let certs = rows.mapped(Certificate::from_row).collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(certs)
        })
    }

    /// Retrieve the certificate's cert data with id from the database
    /// Returns the id of the user the certificate belongs to and the cert data
    pub(crate) async fn get_user_cert_by_id(&self, id: i64) -> Result<Certificate> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, name, created_on, valid_until, data, password, user_id, type, renew_method, ca_id, revoked_at FROM user_certificates WHERE id = ?1")?;

            let cert = stmt.query_row(rusqlite::params_from_iter([id]), Certificate::from_row)?;

            Ok(cert)
        })
    }

    /// Retrieve the certificate's cert data with id from the database
    /// Returns the id of the user the certificate belongs to and the cert password
    pub(crate) async fn get_user_cert_password(&self, id: i64) -> Result<(i64, String)> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT user_id, password FROM user_certificates WHERE id = ?1")?;

            Ok(stmt.query_row(
                params![id],
                |row| Ok((row.get(0)?, row.get(1).unwrap_or_default())),
            )?)
        })
    }

    /// Insert a new certificate into the database
    /// Adds id to Certificate struct
    pub(crate) async fn insert_user_cert(&self, mut cert: Certificate) -> Result<Certificate> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO user_certificates (name, created_on, valid_until, data, password, type, renew_method, ca_id, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![cert.name, cert.created_on, cert.valid_until, cert.data, cert.password, cert.certificate_type as u8, cert.renew_method as u8, cert.ca_id, cert.user_id],
            )?;

            cert.id = conn.last_insert_rowid();

            Ok(cert)
        })
    }

    /// Delete a certificate from the database
    pub(crate) async fn delete_user_cert(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM user_certificates WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    pub(crate) async fn update_cert_renew_method(&self, id: i64, renew_method: CertificateRenewMethod) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET renew_method = ?1 WHERE id=?2",
                params![renew_method as u8, id]
            ).map(|_| ())?)
        })
    }

    pub(crate) async fn revoke_user_cert(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET revoked_at = ?1 WHERE id=?2",
                params![chrono::Utc::now().timestamp(), id]
            ).map(|_| ())?)
        })
    }

    /// Add a new user to the database
    pub(crate) async fn insert_user(&self, mut user: User) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO users (name, email, password_hash, oidc_id, role) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![user.name, user.email, user.password_hash.clone().map(|hash| hash.to_string()), user.oidc_id, user.role as u8],
            )?;

            user.id = conn.last_insert_rowid();

            Ok(user)
        })
    }

    /// Delete a user from the database
    pub(crate) async fn delete_user(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM users WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    /// Update a user in the database
    pub(crate) async fn update_user(&self, user: User) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE users SET name = ?1, email =?2 WHERE id=?3",
                params![user.name, user.email, user.id]
            ).map(|_| ())?)
        })
    }

    /// Return a user entry by id from the database
    pub(crate) async fn get_user(&self, id: i64) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE id=?1",
                params![id],
                |row| {
                    let role_number: u8 = row.get(5)?;
                    Ok(User {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: row.get(3).ok(),
                        oidc_id: row.get(4).ok(),
                        role: UserRole::try_from(role_number).unwrap(),
                    })
                }
            )?)
        })
    }

    /// Return a user entry by email from the database
    pub(crate) async fn get_user_by_email(&self, email: String) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE email=?1",
                params![email],
                |row| {
                    let role_number: u8 = row.get(5)?;
                    Ok(User {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: row.get(3).ok(),
                        oidc_id: row.get(4).ok(),
                        role: UserRole::try_from(role_number).map_err(|_| rusqlite::Error::QueryReturnedNoRows)?,
                    })
                }
            )?)
        })
    }

    /// Return all users from the database
    pub(crate) async fn get_all_user(&self) -> Result<Vec<User>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, name, email, role FROM users")?;
            let query = stmt.query([])?;
            Ok(query.map(|row| {
                    Ok(User {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: None,
                        oidc_id: None,
                        role: row.get(3)?
                    })
                })
                .collect()?)
        })
    }

    /// Set a new password for a user
    /// The password needs to be hashed already
    pub(crate) async fn set_user_password(&self, id: i64, password_hash: Password) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE users SET password_hash = ?1 WHERE id=?2",
                params![password_hash.to_string(), id]
            ).map(|_| ())?)
        })
    }

    pub(crate) async fn unset_user_password(&self, id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE users SET password_hash = NULL WHERE id=?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    /// Register a user with an OIDC ID:
    /// If the user does not exist, a new user is created.
    /// If the user already exists and has matching OIDC ID, nothing is done.
    /// If the user already exists but has no OIDC ID, the OIDC ID is added.
    /// If the user already exists but has a different OIDC ID, an error is returned.
    /// The function adds the user id and role to the User struct
    pub(crate) async fn register_oidc_user(&self, mut user: User) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            let existing_oidc_user_option: Option<(i64, UserRole)> = conn.query_row(
                "SELECT id, role FROM users WHERE oidc_id=?1",
                params![user.oidc_id],
                |row| Ok((row.get(0)?, row.get(1)?))
            ).ok();

            if let Some(existing_oidc_user) = existing_oidc_user_option {
                trace!("User with OIDC_ID {:?} already exists", user.oidc_id);
                user.id = existing_oidc_user.0;
                user.role = existing_oidc_user.1;
                Ok(user)
            } else {
                debug!("User with OIDC_ID {:?} does not exists", user.oidc_id);
                let existing_local_user_option = conn.query_row(
                    "SELECT id, oidc_id, role FROM users WHERE email=?1",
                    params![user.email],
                    |row| {
                        let id = row.get(0)?;
                        let oidc_id: Option<String> = row.get(1)?;
                        let role = row.get(2)?;
                        Ok((id, oidc_id, role))
                    }
                ).ok();
                if let Some(existing_local_user_option) = existing_local_user_option {
                    debug!("OIDC user matched with local account {:?}", existing_local_user_option.0);
                    if existing_local_user_option.1.is_some() {
                        warn!("OIDC user matched with local account but has different OIDC ID already");
                        Err(anyhow!("OIDC Subject ID mismatch"))
                    } else {
                        debug!("Adding OIDC_ID {:?} to local account {:?}", user.oidc_id, existing_local_user_option.0);
                        conn.execute(
                            "UPDATE users SET oidc_id = ?1 WHERE id=?2",
                            params![user.oidc_id, existing_local_user_option.0]
                        )?;
                        user.id = existing_local_user_option.0;
                        user.role = existing_local_user_option.2;
                        Ok(user)
                    }
                } else {
                    debug!("New local account is created for OIDC user");
                    conn.execute(
                        "INSERT INTO users (name, email, password_hash, oidc_id, role) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![user.name, user.email, user.password_hash.clone().map(|hash| hash.to_string()), user.oidc_id, user.role as u8],
                    )?;
                    user.id = conn.last_insert_rowid();
                    Ok(user)
                }
            }
        })
    }

    /// Check if the database is setup
    /// Returns true if the database contains at least one user
    /// Returns false if the database is empty
    pub(crate) async fn is_setup(&self) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id FROM users",
                [],
                |_| Ok(())
            )?)
        })
    }

    pub(crate) async fn insert_acme_account(
        &self,
        name: String,
        allowed_domains: String,
        eab_kid: String,
        eab_hmac_key: Vec<u8>,
        ca_id: Option<i64>,
        user_id: i64,
        auto_validate: bool,
    ) -> Result<AcmeAccount> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let id = db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO acme_accounts (name, allowed_domains, eab_kid, eab_hmac_key, status, ca_id, contacts, created_on, user_id, auto_validate) \
                 VALUES (?1, ?2, ?3, ?4, 'pending', ?5, '', ?6, ?7, ?8)",
                params![name, allowed_domains, eab_kid, eab_hmac_key, ca_id, now, user_id, auto_validate],
            )?;
            Ok::<i64, anyhow::Error>(conn.last_insert_rowid())
        })?;
        self.get_acme_account(id).await
    }

    pub(crate) async fn get_acme_account(&self, id: i64) -> Result<AcmeAccount> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, allowed_domains, eab_kid, eab_hmac_key, acme_jwk, status, ca_id, contacts, created_on, user_id, auto_validate \
                 FROM acme_accounts WHERE id = ?1",
                params![id],
                acme_account_from_row,
            )?)
        })
    }

    pub(crate) async fn get_acme_account_by_eab_kid(&self, eab_kid: String) -> Result<AcmeAccount> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, allowed_domains, eab_kid, eab_hmac_key, acme_jwk, status, ca_id, contacts, created_on, user_id, auto_validate \
                 FROM acme_accounts WHERE eab_kid = ?1",
                params![eab_kid],
                acme_account_from_row,
            )?)
        })
    }

    pub(crate) async fn get_all_acme_accounts(&self) -> Result<Vec<AcmeAccount>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, name, allowed_domains, eab_kid, eab_hmac_key, acme_jwk, status, ca_id, contacts, created_on, user_id, auto_validate \
                 FROM acme_accounts ORDER BY id ASC",
            )?;
            let rows = stmt.query([])?;
            Ok(rows
                .mapped(acme_account_from_row)
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) async fn update_acme_account(
        &self,
        id: i64,
        name: Option<String>,
        allowed_domains: Option<String>,
        ca_id: Option<Option<i64>>,
        status: Option<String>,
        auto_validate: Option<bool>,
    ) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            let mut set_clauses: Vec<String> = Vec::new();
            let mut params_boxed: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(ref v) = name {
                set_clauses.push(format!("name = ?{}", params_boxed.len() + 1));
                params_boxed.push(Box::new(v.clone()));
            }
            if let Some(ref v) = allowed_domains {
                set_clauses.push(format!("allowed_domains = ?{}", params_boxed.len() + 1));
                params_boxed.push(Box::new(v.clone()));
            }
            if let Some(ref v) = ca_id {
                set_clauses.push(format!("ca_id = ?{}", params_boxed.len() + 1));
                params_boxed.push(Box::new(*v));
            }
            if let Some(ref v) = status {
                set_clauses.push(format!("status = ?{}", params_boxed.len() + 1));
                params_boxed.push(Box::new(v.clone()));
            }
            if let Some(v) = auto_validate {
                set_clauses.push(format!("auto_validate = ?{}", params_boxed.len() + 1));
                params_boxed.push(Box::new(v as i64));
            }

            if set_clauses.is_empty() {
                return Ok(());
            }

            let id_param_idx = params_boxed.len() + 1;
            params_boxed.push(Box::new(id));

            let query = format!(
                "UPDATE acme_accounts SET {} WHERE id = ?{}",
                set_clauses.join(", "),
                id_param_idx,
            );

            conn.execute(&query, rusqlite::params_from_iter(params_boxed))?;
            Ok(())
        })
    }

    pub(crate) async fn set_acme_account_jwk(
        &self,
        id: i64,
        jwk: String,
        contacts: String,
        jwk_thumbprint: String,
    ) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE acme_accounts SET acme_jwk = ?1, contacts = ?2, status = 'valid', jwk_thumbprint = ?4 WHERE id = ?3",
                params![jwk, contacts, id, jwk_thumbprint],
            )?;
            Ok(())
        })
    }

    pub(crate) async fn get_acme_account_by_jwk_thumbprint(&self, thumbprint: String) -> Result<AcmeAccount> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, allowed_domains, eab_kid, eab_hmac_key, acme_jwk, status, ca_id, contacts, created_on, user_id, auto_validate \
                 FROM acme_accounts WHERE jwk_thumbprint = ?1",
                params![thumbprint],
                acme_account_from_row,
            )?)
        })
    }

    pub(crate) async fn insert_acme_order(
        &self,
        account_id: i64,
        identifiers: String,
        not_after: i64,
        expires: i64,
        client_ip: Option<String>,
    ) -> Result<i64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO acme_orders (account_id, status, identifiers, not_after, expires, created_on, client_ip) \
                 VALUES (?1, 'pending', ?2, ?3, ?4, ?5, ?6)",
                params![account_id, identifiers, not_after, expires, now, client_ip],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    pub(crate) async fn count_recent_orders_for_account(&self, account_id: i64, window_ms: i64) -> Result<i64> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
            - window_ms;

        db_do!(self.pool, |conn: &Connection| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM acme_orders WHERE account_id = ?1 AND created_on > ?2",
                params![account_id, cutoff],
                |row| row.get(0),
            )?;
            Ok(count)
        })
    }

    pub(crate) async fn get_acme_order(&self, id: i64) -> Result<AcmeOrderRow> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, account_id, status, identifiers, not_after, expires, certificate_id, created_on, client_ip, error \
                 FROM acme_orders WHERE id = ?1",
                params![id],
                order_row_from_row,
            )?)
        })
    }

    pub(crate) async fn update_acme_order_status(
        &self,
        id: i64,
        status: String,
        certificate_id: Option<i64>,
        error: Option<String>,
    ) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE acme_orders SET status = ?1, certificate_id = ?2, error = ?3 WHERE id = ?4",
                params![status, certificate_id, error, id],
            )?;
            Ok(())
        })
    }

    pub(crate) async fn get_all_acme_orders(&self) -> Result<Vec<AdminAcmeOrder>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT o.id, o.account_id, a.name, o.status, o.identifiers, \
                        o.not_after, o.expires, o.certificate_id, o.created_on, o.client_ip, o.error \
                 FROM acme_orders o \
                 JOIN acme_accounts a ON o.account_id = a.id \
                 ORDER BY o.id ASC",
            )?;
            let rows = stmt.query([])?;
            Ok(rows.mapped(|row| {
                let identifiers_json: String = row.get(4)?;
                let identifiers: Vec<AcmeIdentifier> = serde_json::from_str(&identifiers_json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    ))?;
                Ok(AdminAcmeOrder {
                    id: row.get(0)?,
                    account_id: row.get(1)?,
                    account_name: row.get(2)?,
                    status: row.get(3)?,
                    identifiers,
                    not_after: row.get(5)?,
                    expires: row.get(6)?,
                    certificate_id: row.get(7)?,
                    created_on: row.get(8)?,
                    client_ip: row.get(9)?,
                    error: row.get(10)?,
                })
            }).collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) async fn get_orders_by_account(&self, account_id: i64) -> Result<Vec<AcmeOrderRow>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, account_id, status, identifiers, not_after, expires, certificate_id, created_on, client_ip, error \
                 FROM acme_orders WHERE account_id = ?1 ORDER BY id ASC",
            )?;
            let rows = stmt.query(params![account_id])?;
            Ok(rows
                .mapped(order_row_from_row)
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) async fn update_acme_order_identifier_status(
        &self,
        order_id: i64,
        domain_idx: usize,
        status: String,
    ) -> Result<()> {
        let path = format!("$[{domain_idx}].status");
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE acme_orders SET identifiers = json_set(identifiers, ?1, ?2) WHERE id = ?3",
                params![path, status, order_id],
            )?;
            Ok(())
        })
    }

    pub(crate) async fn cleanup_expired_orders(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "DELETE FROM acme_orders WHERE expires < ?1",
                params![now],
            )?;
            Ok(())
        })
    }

    pub(crate) async fn insert_acme_nonce(&self, nonce: String) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO acme_nonces (nonce, created_on) VALUES (?1, ?2)",
                params![nonce, now],
            )?;
            Ok(())
        })
    }

    pub(crate) async fn validate_and_delete_nonce(&self, nonce: String) -> Result<bool> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
            - 3_600_000; // 1 hour TTL

        db_do!(self.pool, |conn: &Connection| {
            let rows_affected = conn.execute(
                "DELETE FROM acme_nonces WHERE nonce = ?1 AND created_on > ?2",
                params![nonce, cutoff],
            )?;
            Ok(rows_affected > 0)
        })
    }

    pub(crate) async fn check_cert_acme_account(&self, cert_id: i64, acme_account_id: i64) -> Result<bool> {
        db_do!(self.pool, |conn: &Connection| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE id = ?1 AND acme_account_id = ?2",
                params![cert_id, acme_account_id],
                |row| row.get(0),
            )?;
            Ok(count > 0)
        })
    }

    pub(crate) async fn set_cert_serial(&self, cert_id: i64, serial_hex: String) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE user_certificates SET serial_hex = ?1 WHERE id = ?2",
                params![serial_hex, cert_id],
            )?;
            Ok(())
        })
    }

    pub(crate) async fn get_cert_id_by_serial_hex(&self, serial_hex: String) -> Result<Option<i64>> {
        db_do!(self.pool, |conn: &Connection| {
            let result = conn.query_row(
                "SELECT id FROM user_certificates WHERE serial_hex = ?1 AND revoked_at IS NULL",
                params![serial_hex],
                |row| row.get::<_, i64>(0),
            );
            match result {
                Ok(id) => Ok(Some(id)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(anyhow::anyhow!(e)),
            }
        })
    }

    pub(crate) async fn set_cert_acme_account(&self, cert_id: i64, acme_account_id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "UPDATE user_certificates SET acme_account_id = ?1 WHERE id = ?2",
                params![acme_account_id, cert_id],
            )?;
            Ok(())
        })
    }

    pub(crate) async fn cleanup_old_nonces(&self) -> Result<()> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
            - 3_600_000; // 1 hour in milliseconds

        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "DELETE FROM acme_nonces WHERE created_on < ?1",
                params![cutoff],
            )?;
            Ok(())
        })
    }
}

fn acme_account_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AcmeAccount> {
    Ok(AcmeAccount {
        id: row.get(0)?,
        name: row.get(1)?,
        allowed_domains: row.get(2)?,
        eab_kid: row.get(3)?,
        eab_hmac_key: row.get(4)?,
        acme_jwk: row.get(5)?,
        status: row.get(6)?,
        ca_id: row.get(7)?,
        contacts: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
        created_on: row.get(9)?,
        user_id: row.get(10)?,
        auto_validate: row.get::<_, i64>(11).unwrap_or(0) != 0,
    })
}

fn order_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AcmeOrderRow> {
    Ok(AcmeOrderRow {
        id: row.get(0)?,
        account_id: row.get(1)?,
        status: row.get(2)?,
        identifiers: row.get(3)?,
        not_after: row.get(4)?,
        expires: row.get(5)?,
        certificate_id: row.get(6)?,
        created_on: row.get(7)?,
        client_ip: row.get(8)?,
        error: row.get(9)?,
    })
}