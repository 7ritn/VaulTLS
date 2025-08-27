use crate::cert::{Certificate, CA};
use crate::constants::{DB_FILE_PATH, TEMP_DB_FILE_PATH};
use crate::data::enums::{CertificateRenewMethod, UserRole};
use crate::data::objects::User;
use crate::data::tenant::Tenant;
use crate::data::token::ApiToken;
use crate::data::audit::AuditEvent;
use crate::data::profile::Profile;
use crate::helper::get_secret;
use anyhow::anyhow;
use anyhow::Result;
use include_dir::{include_dir, Dir};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{params, Connection};
use rusqlite_migration::Migrations;
use std::fs;
use std::path::Path;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tracing::{debug, info, trace, warn};
use crate::auth::password_auth::Password;

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

        // ToDo fix when to migrate
        if !db_encrypted {
            if let Ok(ref db_secret_result) = db_secret_result {
                let db_secret = db_secret_result.clone();
                Self::create_encrypt_db(&connection, &db_secret)?;
                drop(connection);
                Self::migrate_to_encrypted_db()?;
                info!("Migrated to encrypted database");
                let manager = SqliteConnectionManager::file(DB_FILE_PATH)
                    .with_init(move |conn| {
                        conn.pragma_update(None, "key", db_secret.clone())?;
                        conn.pragma_update(None, "foreign_keys", "ON")?;
                        Ok(())
                    });

                let pool = Pool::builder()
                    .max_size(1)
                    .build(manager)?;

                return Ok(Self { pool });
            }
        }

        Ok(Self { pool })
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
            if let Some(stored_password) = user.password_hash {
                if stored_password.verify("") {
                    // Password stored is empty
                    info!("Password for user {} is empty, disabling password", user.name);
                    self.unset_user_password(user.id).await?;
                }
            }
        }
        Ok(())
    }

    /// Insert a new CA certificate into the database
    /// Adds id to the Certificate struct
    pub(crate) async fn insert_ca(
        &self,
        ca: CA
    ) -> Result<i64> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO ca_certificates (created_on, valid_until, certificate, key) VALUES (?1, ?2, ?3, ?4)",
                params![ca.created_on, ca.valid_until, ca.cert, ca.key],
            )?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Retrieve the most recent CA entry from the database
    pub(crate) async fn get_current_ca(&self) -> Result<CA> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT * FROM ca_certificates ORDER BY id DESC LIMIT 1")?;

            stmt.query_row([], |row| {
                Ok(CA{
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    tenant_id: row.get(5).unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string()),
                    name: row.get(6).unwrap_or(None),
                    key_algorithm: row.get(7).unwrap_or_else(|_| "rsa-2048".to_string()),
                    path_len: row.get(8).unwrap_or(None),
                    basic_constraints: row.get(9).unwrap_or(None),
                    crl_distribution_points: row.get(10).unwrap_or(None),
                    authority_info_access: row.get(11).unwrap_or(None),
                    is_active: row.get(12).unwrap_or(true),
                })
            }).map_err(|_| anyhow!("VaulTLS has not been set-up yet"))
        })
    }

    /// Retrieve all user certificates from the database
    /// If user_id is Some, only certificates for that user are returned
    /// If user_id is None, all certificates are returned
    pub(crate) async fn get_all_user_cert(&self, user_id: Option<i64>) -> Result<Vec<Certificate>> {
        db_do!(self.pool, |conn: &Connection| {
            let query = match user_id {
                Some(_) => "SELECT id, name, created_on, valid_until, pkcs12, pkcs12_password, user_id, type, renew_method FROM user_certificates WHERE user_id = ?1",
                None => "SELECT id, name, created_on, valid_until, pkcs12, pkcs12_password, user_id, type, renew_method FROM user_certificates"
            };
            let mut stmt = conn.prepare(query)?;
            let rows = match user_id {
                Some(id) => stmt.query(params![id])?,
                None => stmt.query([])?,
            };
            Ok(rows.map(|row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    pkcs12: row.get(4)?,
                    pkcs12_password: row.get(5).unwrap_or_default(),
                    user_id: row.get(6)?,
                    certificate_type: row.get(7)?,
                    renew_method: row.get(8)?,
                    ..Default::default()
                })
            })
            .collect()?)
        })
    }

    /// Retrieve the certificate's PKCS12  data with id from the database
    /// Returns the id of the user the certificate belongs to and the PKCS12 data
    pub(crate) async fn get_user_cert_pkcs12(&self, id: i64) -> Result<(i64, String, Vec<u8>)> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT user_id, name, pkcs12 FROM user_certificates WHERE id = ?1")?;

            Ok(stmt.query_row(
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?)
        })
    }

    /// Retrieve the certificate's PKCS12 data with id from the database
    /// Returns the id of the user the certificate belongs to and the PKCS12 password
    pub(crate) async fn get_user_cert_pkcs12_password(&self, id: i64) -> Result<(i64, String)> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT user_id, pkcs12_password FROM user_certificates WHERE id = ?1")?;

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
                "INSERT INTO user_certificates (name, created_on, valid_until, pkcs12, pkcs12_password, type, renew_method, ca_id, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![cert.name, cert.created_on, cert.valid_until, cert.pkcs12, cert.pkcs12_password, cert.certificate_type as u8, cert.renew_method as u8, cert.ca_id, cert.user_id],
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
                "SELECT id, name, email, password_hash, oidc_id, role, tenant_id FROM users WHERE id=?1",
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
                        tenant_id: row.get(6).unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string()),
                    })
                }
            )?)
        })
    }

    /// Return a user entry by email from the database
    pub(crate) async fn get_user_by_email(&self, email: String) -> Result<User> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, email, password_hash, oidc_id, role, tenant_id FROM users WHERE email=?1",
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
                        tenant_id: row.get(6).unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string()),
                    })
                }
            )?)
        })
    }

    /// Return all users from the database
    pub(crate) async fn get_all_user(&self) -> Result<Vec<User>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, name, email, role, tenant_id FROM users")?;
            let query = stmt.query([])?;
            Ok(query.map(|row| {
                    Ok(User {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: None,
                        oidc_id: None,
                        role: row.get(3)?,
                        tenant_id: row.get(4).unwrap_or_else(|_| "00000000-0000-0000-0000-000000000000".to_string()),
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

    // ===== TENANT OPERATIONS =====

    /// Insert a new tenant into the database
    pub(crate) async fn insert_tenant(&self, tenant: Tenant) -> Result<Tenant> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO tenants (id, name, created_at, is_active) VALUES (?1, ?2, ?3, ?4)",
                params![tenant.id, tenant.name, tenant.created_at, tenant.is_active],
            )?;
            Ok(tenant)
        })
    }

    /// Get a tenant by ID
    pub(crate) async fn get_tenant(&self, id: &str) -> Result<Tenant> {
        let id = id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, created_at, is_active FROM tenants WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Tenant {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        created_at: row.get(2)?,
                        is_active: row.get(3)?,
                    })
                }
            )?)
        })
    }

    /// Get all tenants
    pub(crate) async fn get_all_tenants(&self) -> Result<Vec<Tenant>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare("SELECT id, name, created_at, is_active FROM tenants ORDER BY name")?;
            let rows = stmt.query_map([], |row| {
                Ok(Tenant {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    is_active: row.get(3)?,
                })
            })?;

            let mut tenants = Vec::new();
            for tenant in rows {
                tenants.push(tenant?);
            }
            Ok(tenants)
        })
    }

    /// Update a tenant
    pub(crate) async fn update_tenant(&self, tenant: &Tenant) -> Result<()> {
        let tenant = tenant.clone();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE tenants SET name = ?1, is_active = ?2 WHERE id = ?3",
                params![tenant.name, tenant.is_active, tenant.id]
            ).map(|_| ())?)
        })
    }

    /// Delete a tenant (and all associated data)
    pub(crate) async fn delete_tenant(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM tenants WHERE id = ?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    // ===== API TOKEN OPERATIONS =====

    /// Insert a new API token into the database
    pub(crate) async fn insert_api_token(&self, token: ApiToken) -> Result<ApiToken> {
        db_do!(self.pool, |conn: &Connection| {
            let scopes_json = serde_json::to_string(&token.scopes)?;

            conn.execute(
                "INSERT INTO api_tokens (id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    token.id, token.prefix, token.hash, token.salt, scopes_json, token.description,
                    token.is_enabled, token.revoked_at, token.last_used_at, token.expires_at,
                    token.created_at, token.created_by_user_id, token.tenant_id, token.rate_limit_per_minute
                ],
            )?;

            Ok(token)
        })
    }

    /// Get an API token by prefix
    pub(crate) async fn get_api_token_by_prefix(&self, prefix: &str) -> Result<ApiToken> {
        let prefix = prefix.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute FROM api_tokens WHERE prefix = ?1",
                params![prefix],
                |row| {
                    let scopes_json: String = row.get(4)?;
                    let scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();

                    Ok(ApiToken {
                        id: row.get(0)?,
                        prefix: row.get(1)?,
                        hash: row.get(2)?,
                        salt: row.get(3)?,
                        scopes,
                        description: row.get(5)?,
                        is_enabled: row.get(6)?,
                        revoked_at: row.get(7)?,
                        last_used_at: row.get(8)?,
                        expires_at: row.get(9)?,
                        created_at: row.get(10)?,
                        created_by_user_id: row.get(11)?,
                        tenant_id: row.get(12)?,
                        rate_limit_per_minute: row.get(13)?,
                    })
                }
            )?)
        })
    }

    /// Get an API token by ID
    pub(crate) async fn get_api_token(&self, id: &str) -> Result<ApiToken> {
        let id = id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute FROM api_tokens WHERE id = ?1",
                params![id],
                |row| {
                    let scopes_json: String = row.get(4)?;
                    let scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();

                    Ok(ApiToken {
                        id: row.get(0)?,
                        prefix: row.get(1)?,
                        hash: row.get(2)?,
                        salt: row.get(3)?,
                        scopes,
                        description: row.get(5)?,
                        is_enabled: row.get(6)?,
                        revoked_at: row.get(7)?,
                        last_used_at: row.get(8)?,
                        expires_at: row.get(9)?,
                        created_at: row.get(10)?,
                        created_by_user_id: row.get(11)?,
                        tenant_id: row.get(12)?,
                        rate_limit_per_minute: row.get(13)?,
                    })
                }
            )?)
        })
    }

    /// Get all API tokens for a tenant
    pub(crate) async fn get_api_tokens_by_tenant(&self, tenant_id: &str) -> Result<Vec<ApiToken>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute FROM api_tokens WHERE tenant_id = ?1 ORDER BY created_at DESC"
            )?;

            let rows = stmt.query_map(params![tenant_id], |row| {
                let scopes_json: String = row.get(4)?;
                let scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();

                Ok(ApiToken {
                    id: row.get(0)?,
                    prefix: row.get(1)?,
                    hash: row.get(2)?,
                    salt: row.get(3)?,
                    scopes,
                    description: row.get(5)?,
                    is_enabled: row.get(6)?,
                    revoked_at: row.get(7)?,
                    last_used_at: row.get(8)?,
                    expires_at: row.get(9)?,
                    created_at: row.get(10)?,
                    created_by_user_id: row.get(11)?,
                    tenant_id: row.get(12)?,
                    rate_limit_per_minute: row.get(13)?,
                })
            })?;

            let mut tokens = Vec::new();
            for token in rows {
                tokens.push(token?);
            }
            Ok(tokens)
        })
    }

    /// Update an API token
    pub(crate) async fn update_api_token(&self, token: &ApiToken) -> Result<()> {
        let token = token.clone();
        db_do!(self.pool, |conn: &Connection| {
            let scopes_json = serde_json::to_string(&token.scopes)?;

            Ok(conn.execute(
                "UPDATE api_tokens SET scopes = ?1, description = ?2, is_enabled = ?3, revoked_at = ?4, last_used_at = ?5, expires_at = ?6, rate_limit_per_minute = ?7 WHERE id = ?8",
                params![
                    scopes_json, token.description, token.is_enabled, token.revoked_at,
                    token.last_used_at, token.expires_at, token.rate_limit_per_minute, token.id
                ]
            ).map(|_| ())?)
        })
    }

    /// Update token hash and salt (for rotation)
    pub(crate) async fn update_api_token_hash(&self, id: &str, hash: &str, salt: &str) -> Result<()> {
        let id = id.to_string();
        let hash = hash.to_string();
        let salt = salt.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE api_tokens SET hash = ?1, salt = ?2 WHERE id = ?3",
                params![hash, salt, id]
            ).map(|_| ())?)
        })
    }

    /// Delete an API token
    pub(crate) async fn delete_api_token(&self, id: &str) -> Result<()> {
        let id = id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM api_tokens WHERE id = ?1",
                params![id]
            ).map(|_| ())?)
        })
    }

    // ===== AUDIT OPERATIONS =====

    /// Insert an audit event
    pub(crate) async fn insert_audit_event(&self, mut event: AuditEvent) -> Result<AuditEvent> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO audit_events (event_type, resource_type, resource_id, user_id, token_prefix, tenant_id, endpoint, method, status_code, duration_ms, ip_address, user_agent, request_body, response_body, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    event.event_type, event.resource_type, event.resource_id, event.user_id,
                    event.token_prefix, event.tenant_id, event.endpoint, event.method,
                    event.status_code, event.duration_ms, event.ip_address, event.user_agent,
                    event.request_body, event.response_body, event.created_at
                ],
            )?;

            event.id = conn.last_insert_rowid();
            Ok(event)
        })
    }

    /// Get audit events with filtering
    pub(crate) async fn get_audit_events(
        &self,
        tenant_id: Option<&str>,
        event_type: Option<&str>,
        resource_type: Option<&str>,
        start_date: Option<i64>,
        end_date: Option<i64>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<AuditEvent>> {
        let tenant_id = tenant_id.map(|s| s.to_string());
        let event_type = event_type.map(|s| s.to_string());
        let resource_type = resource_type.map(|s| s.to_string());
        db_do!(self.pool, |conn: &Connection| {
            let mut query = "SELECT id, event_type, resource_type, resource_id, user_id, token_prefix, tenant_id, endpoint, method, status_code, duration_ms, ip_address, user_agent, request_body, response_body, created_at FROM audit_events WHERE 1=1".to_string();
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

            if let Some(tenant_id) = tenant_id {
                query.push_str(" AND tenant_id = ?");
                params.push(Box::new(tenant_id));
            }

            if let Some(event_type) = event_type {
                query.push_str(" AND event_type = ?");
                params.push(Box::new(event_type));
            }

            if let Some(resource_type) = resource_type {
                query.push_str(" AND resource_type = ?");
                params.push(Box::new(resource_type));
            }

            if let Some(start_date) = start_date {
                query.push_str(" AND created_at >= ?");
                params.push(Box::new(start_date));
            }

            if let Some(end_date) = end_date {
                query.push_str(" AND created_at <= ?");
                params.push(Box::new(end_date));
            }

            query.push_str(" ORDER BY created_at DESC");

            if let Some(limit) = limit {
                query.push_str(" LIMIT ?");
                params.push(Box::new(limit));
            }

            if let Some(offset) = offset {
                query.push_str(" OFFSET ?");
                params.push(Box::new(offset));
            }

            let mut stmt = conn.prepare(&query)?;
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

            let rows = stmt.query_map(param_refs.as_slice(), |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    resource_type: row.get(2)?,
                    resource_id: row.get(3)?,
                    user_id: row.get(4)?,
                    token_prefix: row.get(5)?,
                    tenant_id: row.get(6)?,
                    endpoint: row.get(7)?,
                    method: row.get(8)?,
                    status_code: row.get(9)?,
                    duration_ms: row.get(10)?,
                    ip_address: row.get(11)?,
                    user_agent: row.get(12)?,
                    request_body: row.get(13)?,
                    response_body: row.get(14)?,
                    created_at: row.get(15)?,
                })
            })?;

            let mut events = Vec::new();
            for event in rows {
                events.push(event?);
            }
            Ok(events)
        })
    }
}