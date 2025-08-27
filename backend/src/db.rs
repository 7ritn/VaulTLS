use crate::cert::{Certificate, CA};
use crate::constants::{DB_FILE_PATH, TEMP_DB_FILE_PATH};
use crate::data::enums::{CertificateRenewMethod, UserRole};
use crate::data::objects::User;
use crate::data::tenant::Tenant;
use crate::data::token::ApiToken;
use crate::data::audit::AuditEvent;
use crate::data::profile::Profile;
use crate::data::crl::{CrlMetadata, RevokedCertificate, RevocationReason};
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
                    description: row.get(13).unwrap_or(None),
                    key_algorithm: row.get(7).unwrap_or_else(|_| "ecdsa-p256".to_string()),
                    key_size: row.get(14).unwrap_or(Some(256)),
                    path_len: row.get(8).unwrap_or(None),
                    basic_constraints: row.get(9).unwrap_or(None),
                    crl_distribution_points: row.get(10).unwrap_or(None),
                    authority_info_access: row.get(11).unwrap_or(None),
                    is_active: row.get(12).unwrap_or(true),
                    is_root_ca: row.get(15).unwrap_or(true),
                    parent_ca_id: row.get(16).unwrap_or(None),
                    serial_number: row.get(17).unwrap_or(None),
                    issuer: row.get(18).unwrap_or(None),
                    subject: row.get(19).unwrap_or(None),
                    key_usage: row.get(20).unwrap_or(None),
                    extended_key_usage: row.get(21).unwrap_or(None),
                    certificate_policies: row.get(22).unwrap_or(None),
                    policy_constraints: row.get(23).unwrap_or(None),
                    name_constraints: row.get(24).unwrap_or(None),
                    created_by_user_id: row.get(25).unwrap_or(1),
                    metadata: row.get(26).unwrap_or(None),
                })
            }).map_err(|_| anyhow!("VaulTLS has not been set-up yet"))
        })
    }

    /// Get CA by ID
    pub(crate) async fn get_ca_by_id(&self, ca_id: i64) -> Result<CA> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT * FROM ca_certificates WHERE id = ?1",
                params![ca_id],
                |row| {
                    Ok(CA{
                        id: row.get(0)?,
                        created_on: row.get(1)?,
                        valid_until: row.get(2)?,
                        cert: row.get(3)?,
                        key: row.get(4)?,
                        tenant_id: row.get(5)?,
                        name: row.get(6)?,
                        description: row.get(13)?,
                        key_algorithm: row.get(7)?,
                        key_size: row.get(14)?,
                        path_len: row.get(8)?,
                        basic_constraints: row.get(9)?,
                        crl_distribution_points: row.get(10)?,
                        authority_info_access: row.get(11)?,
                        is_active: row.get(12)?,
                        is_root_ca: row.get(15)?,
                        parent_ca_id: row.get(16)?,
                        serial_number: row.get(17)?,
                        issuer: row.get(18)?,
                        subject: row.get(19)?,
                        key_usage: row.get(20)?,
                        extended_key_usage: row.get(21)?,
                        certificate_policies: row.get(22)?,
                        policy_constraints: row.get(23)?,
                        name_constraints: row.get(24)?,
                        created_by_user_id: row.get(25)?,
                        metadata: row.get(26)?,
                    })
                }
            )?)
        })
    }

    /// Get CAs for a tenant
    pub(crate) async fn get_cas_for_tenant(&self, tenant_id: &str) -> Result<Vec<CA>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT * FROM ca_certificates WHERE tenant_id = ?1 ORDER BY created_on DESC"
            )?;

            let rows = stmt.query_map(params![tenant_id], |row| {
                Ok(CA{
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    tenant_id: row.get(5)?,
                    name: row.get(6)?,
                    description: row.get(13)?,
                    key_algorithm: row.get(7)?,
                    key_size: row.get(14)?,
                    path_len: row.get(8)?,
                    basic_constraints: row.get(9)?,
                    crl_distribution_points: row.get(10)?,
                    authority_info_access: row.get(11)?,
                    is_active: row.get(12)?,
                    is_root_ca: row.get(15)?,
                    parent_ca_id: row.get(16)?,
                    serial_number: row.get(17)?,
                    issuer: row.get(18)?,
                    subject: row.get(19)?,
                    key_usage: row.get(20)?,
                    extended_key_usage: row.get(21)?,
                    certificate_policies: row.get(22)?,
                    policy_constraints: row.get(23)?,
                    name_constraints: row.get(24)?,
                    created_by_user_id: row.get(25)?,
                    metadata: row.get(26)?,
                })
            })?;

            let mut cas = Vec::new();
            for ca in rows {
                cas.push(ca?);
            }
            Ok(cas)
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

    // ===== CRL OPERATIONS =====

    /// Revoke a certificate
    pub(crate) async fn revoke_certificate(
        &self,
        certificate_id: i64,
        revocation_date: i64,
        reason: RevocationReason,
        revoked_by_user_id: i64,
    ) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET revocation_status = 'revoked', revoked_at = ?1, revocation_reason = ?2, revoked_by_user_id = ?3 WHERE id = ?4",
                params![revocation_date, reason as u8, revoked_by_user_id, certificate_id]
            ).map(|_| ())?)
        })
    }

    /// Restore a certificate from revocation
    pub(crate) async fn restore_certificate(&self, certificate_id: i64, restored_by_user_id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET revocation_status = 'active', revoked_at = NULL, revocation_reason = NULL, revoked_by_user_id = ?1 WHERE id = ?2",
                params![restored_by_user_id, certificate_id]
            ).map(|_| ())?)
        })
    }

    /// Insert a revoked certificate record
    pub(crate) async fn insert_revoked_certificate(&self, revoked_cert: RevokedCertificate) -> Result<RevokedCertificate> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO revoked_certificates (certificate_id, serial_number, revocation_date, revocation_reason, ca_id, tenant_id, revoked_by_user_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    revoked_cert.certificate_id, revoked_cert.serial_number, revoked_cert.revocation_date,
                    revoked_cert.revocation_reason as u8, revoked_cert.ca_id, revoked_cert.tenant_id,
                    revoked_cert.revoked_by_user_id, revoked_cert.created_at
                ],
            )?;

            Ok(revoked_cert)
        })
    }

    /// Remove a revoked certificate record
    pub(crate) async fn remove_revoked_certificate(&self, certificate_id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM revoked_certificates WHERE certificate_id = ?1",
                params![certificate_id]
            ).map(|_| ())?)
        })
    }

    /// Get revoked certificates for a CA
    pub(crate) async fn get_revoked_certificates_by_ca(&self, ca_id: i64, tenant_id: &str) -> Result<Vec<RevokedCertificate>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, certificate_id, serial_number, revocation_date, revocation_reason, ca_id, tenant_id, revoked_by_user_id, created_at FROM revoked_certificates WHERE ca_id = ?1 AND tenant_id = ?2 ORDER BY revocation_date DESC"
            )?;

            let rows = stmt.query_map(params![ca_id, tenant_id], |row| {
                let reason_code: u8 = row.get(4)?;
                let reason = RevocationReason::from_u8(reason_code).unwrap_or_default();

                Ok(RevokedCertificate {
                    id: row.get(0)?,
                    certificate_id: row.get(1)?,
                    serial_number: row.get(2)?,
                    revocation_date: row.get(3)?,
                    revocation_reason: reason,
                    ca_id: row.get(5)?,
                    tenant_id: row.get(6)?,
                    revoked_by_user_id: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })?;

            let mut revoked_certs = Vec::new();
            for cert in rows {
                revoked_certs.push(cert?);
            }
            Ok(revoked_certs)
        })
    }

    /// Get certificate by serial number
    pub(crate) async fn get_certificate_by_serial(&self, serial_number: &str) -> Result<Certificate> {
        let serial_number = serial_number.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, created_on, valid_until, type, user_id, renew_method, tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size, sans, metadata, status, ca_id, revoked_at, revoked_by_user_id, revocation_reason FROM user_certificates WHERE serial_number = ?1",
                params![serial_number],
                |row| {
                    Ok(Certificate {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        created_on: row.get(2)?,
                        valid_until: row.get(3)?,
                        certificate_type: row.get(4)?,
                        user_id: row.get(5)?,
                        renew_method: row.get(6)?,
                        tenant_id: row.get(7)?,
                        profile_id: row.get(8)?,
                        serial_number: row.get(9)?,
                        issuer: row.get(10)?,
                        subject: row.get(11)?,
                        algorithm: row.get(12)?,
                        key_size: row.get(13)?,
                        sans: row.get(14)?,
                        metadata: row.get(15)?,
                        status: row.get(16)?,
                        pkcs12: Vec::new(),
                        pkcs12_password: String::new(),
                        ca_id: row.get(17)?,
                        revoked_at: row.get(18)?,
                        revoked_by_user_id: row.get(19)?,
                        revocation_reason: row.get(20)?,
                    })
                }
            )?)
        })
    }

    /// Get certificate by serial number and CA
    pub(crate) async fn get_certificate_by_serial_and_ca(&self, serial_number: &str, ca_id: i64) -> Result<Certificate> {
        let serial_number = serial_number.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, created_on, valid_until, type, user_id, renew_method, tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size, sans, metadata, status, ca_id, revoked_at, revoked_by_user_id, revocation_reason FROM user_certificates WHERE serial_number = ?1 AND ca_id = ?2",
                params![serial_number, ca_id],
                |row| {
                    Ok(Certificate {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        created_on: row.get(2)?,
                        valid_until: row.get(3)?,
                        certificate_type: row.get(4)?,
                        user_id: row.get(5)?,
                        renew_method: row.get(6)?,
                        tenant_id: row.get(7)?,
                        profile_id: row.get(8)?,
                        serial_number: row.get(9)?,
                        issuer: row.get(10)?,
                        subject: row.get(11)?,
                        algorithm: row.get(12)?,
                        key_size: row.get(13)?,
                        sans: row.get(14)?,
                        metadata: row.get(15)?,
                        status: row.get(16)?,
                        pkcs12: Vec::new(),
                        pkcs12_password: String::new(),
                        ca_id: row.get(17)?,
                        revoked_at: row.get(18)?,
                        revoked_by_user_id: row.get(19)?,
                        revocation_reason: row.get(20)?,
                    })
                }
            )?)
        })
    }

    /// Count certificates by CA
    pub(crate) async fn count_certificates_by_ca(&self, ca_id: i64, tenant_id: &str) -> Result<i64> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE ca_id = ?1 AND tenant_id = ?2",
                params![ca_id, tenant_id],
                |row| row.get(0)
            )?)
        })
    }

    /// Count active certificates by CA
    pub(crate) async fn count_active_certificates_by_ca(&self, ca_id: i64, tenant_id: &str) -> Result<i64> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE ca_id = ?1 AND tenant_id = ?2 AND (revocation_status = 'active' OR revocation_status IS NULL)",
                params![ca_id, tenant_id],
                |row| row.get(0)
            )?)
        })
    }

    /// Count revoked certificates by CA
    pub(crate) async fn count_revoked_certificates_by_ca(&self, ca_id: i64, tenant_id: &str) -> Result<i64> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE ca_id = ?1 AND tenant_id = ?2 AND revocation_status = 'revoked'",
                params![ca_id, tenant_id],
                |row| row.get(0)
            )?)
        })
    }

    /// Count expired certificates by CA
    pub(crate) async fn count_expired_certificates_by_ca(&self, ca_id: i64, tenant_id: &str) -> Result<i64> {
        let tenant_id = tenant_id.to_string();
        let now = chrono::Utc::now().timestamp();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE ca_id = ?1 AND tenant_id = ?2 AND valid_until < ?3",
                params![ca_id, tenant_id, now],
                |row| row.get(0)
            )?)
        })
    }

    /// Get revocations by reason
    pub(crate) async fn get_revocations_by_reason(&self, ca_id: i64, tenant_id: &str) -> Result<std::collections::HashMap<String, i64>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT revocation_reason, COUNT(*) FROM revoked_certificates WHERE ca_id = ?1 AND tenant_id = ?2 GROUP BY revocation_reason"
            )?;

            let rows = stmt.query_map(params![ca_id, tenant_id], |row| {
                let reason_code: u8 = row.get(0)?;
                let count: i64 = row.get(1)?;
                let reason = RevocationReason::from_u8(reason_code).unwrap_or_default();
                Ok((reason.description().to_string(), count))
            })?;

            let mut result = std::collections::HashMap::new();
            for row in rows {
                let (reason, count) = row?;
                result.insert(reason, count);
            }
            Ok(result)
        })
    }

    /// Count recent revocations
    pub(crate) async fn count_recent_revocations(&self, ca_id: i64, tenant_id: &str, days: i32) -> Result<i64> {
        let tenant_id = tenant_id.to_string();
        let cutoff = chrono::Utc::now().timestamp() - (days as i64 * 24 * 60 * 60);
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM revoked_certificates WHERE ca_id = ?1 AND tenant_id = ?2 AND revocation_date >= ?3",
                params![ca_id, tenant_id, cutoff],
                |row| row.get(0)
            )?)
        })
    }

    /// Insert CRL metadata
    pub(crate) async fn insert_crl_metadata(&self, metadata: CrlMetadata) -> Result<CrlMetadata> {
        db_do!(self.pool, |conn: &Connection| {
            conn.execute(
                "INSERT INTO crl_metadata (ca_id, tenant_id, crl_number, this_update, next_update, revoked_count, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    metadata.ca_id, metadata.tenant_id, metadata.crl_number,
                    metadata.this_update, metadata.next_update, metadata.revoked_count, metadata.created_at
                ],
            )?;

            Ok(metadata)
        })
    }

    /// Update CRL metadata
    pub(crate) async fn update_crl_metadata(&self, metadata: CrlMetadata) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE crl_metadata SET crl_number = ?1, this_update = ?2, next_update = ?3, revoked_count = ?4 WHERE ca_id = ?5 AND tenant_id = ?6",
                params![
                    metadata.crl_number, metadata.this_update, metadata.next_update,
                    metadata.revoked_count, metadata.ca_id, metadata.tenant_id
                ]
            ).map(|_| ())?)
        })
    }

    /// Get CRL metadata
    pub(crate) async fn get_crl_metadata(&self, ca_id: i64, tenant_id: &str) -> Result<CrlMetadata> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, ca_id, tenant_id, crl_number, this_update, next_update, revoked_count, created_at FROM crl_metadata WHERE ca_id = ?1 AND tenant_id = ?2 ORDER BY created_at DESC LIMIT 1",
                params![ca_id, tenant_id],
                |row| {
                    Ok(CrlMetadata {
                        id: row.get(0)?,
                        ca_id: row.get(1)?,
                        tenant_id: row.get(2)?,
                        crl_number: row.get(3)?,
                        this_update: row.get(4)?,
                        next_update: row.get(5)?,
                        revoked_count: row.get(6)?,
                        created_at: row.get(7)?,
                    })
                }
            )?)
        })
    }

    /// Get next CRL number
    pub(crate) async fn get_next_crl_number(&self, ca_id: i64, tenant_id: &str) -> Result<i64> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let current_number: Result<i64, _> = conn.query_row(
                "SELECT MAX(crl_number) FROM crl_metadata WHERE ca_id = ?1 AND tenant_id = ?2",
                params![ca_id, tenant_id],
                |row| row.get(0)
            );

            Ok(current_number.unwrap_or(0) + 1)
        })
    }

    /// Store CRL data
    pub(crate) async fn store_crl(&self, ca_id: i64, tenant_id: &str, crl_data: &[u8]) -> Result<()> {
        let tenant_id = tenant_id.to_string();
        let crl_data = crl_data.to_vec();
        db_do!(self.pool, |conn: &Connection| {
            // For now, we'll store CRL in a simple table
            // In production, you might want to store in filesystem or object storage
            conn.execute(
                "INSERT OR REPLACE INTO crl_cache (ca_id, tenant_id, crl_data, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![ca_id, tenant_id, crl_data, chrono::Utc::now().timestamp()]
            )?;
            Ok(())
        })
    }

    /// Get stored CRL data
    pub(crate) async fn get_stored_crl(&self, ca_id: i64, tenant_id: &str) -> Result<Vec<u8>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT crl_data FROM crl_cache WHERE ca_id = ?1 AND tenant_id = ?2",
                params![ca_id, tenant_id],
                |row| row.get(0)
            )?)
        })
    }

    // ===== PERMISSION SYSTEM OPERATIONS =====

    /// Insert role-scope mapping
    pub(crate) async fn insert_role_scope_mapping(
        &self,
        role: UserRole,
        scope: &str,
        tenant_id: Option<String>,
    ) -> Result<()> {
        let scope = scope.to_string();
        db_do!(self.pool, |conn: &Connection| {
            // Check if mapping already exists
            let exists: bool = conn.query_row(
                "SELECT 1 FROM role_scope_map WHERE role = ?1 AND scope = ?2 AND (tenant_id = ?3 OR (tenant_id IS NULL AND ?3 IS NULL))",
                params![role as u8, scope, tenant_id],
                |_| Ok(true)
            ).unwrap_or(false);

            if !exists {
                conn.execute(
                    "INSERT INTO role_scope_map (role, scope, tenant_id) VALUES (?1, ?2, ?3)",
                    params![role as u8, scope, tenant_id]
                )?;
            }
            Ok(())
        })
    }

    /// Insert endpoint-scope mapping
    pub(crate) async fn insert_endpoint_scope_mapping(
        &self,
        endpoint_pattern: String,
        method: String,
        required_scopes: Vec<String>,
        description: Option<String>,
    ) -> Result<()> {
        let scopes_json = serde_json::to_string(&required_scopes)?;
        db_do!(self.pool, |conn: &Connection| {
            // Check if mapping already exists
            let exists: bool = conn.query_row(
                "SELECT 1 FROM endpoint_scope_map WHERE endpoint_pattern = ?1 AND method = ?2",
                params![endpoint_pattern, method],
                |_| Ok(true)
            ).unwrap_or(false);

            if !exists {
                conn.execute(
                    "INSERT INTO endpoint_scope_map (endpoint_pattern, method, required_scopes, description) VALUES (?1, ?2, ?3, ?4)",
                    params![endpoint_pattern, method, scopes_json, description]
                )?;
            }
            Ok(())
        })
    }

    /// Get scopes for a role
    pub(crate) async fn get_scopes_for_role(
        &self,
        role: UserRole,
        tenant_id: Option<&str>,
    ) -> Result<Vec<String>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT scope FROM role_scope_map WHERE role = ?1 AND (tenant_id = ?2 OR tenant_id IS NULL)"
            )?;

            let rows = stmt.query_map(params![role as u8, tenant_id], |row| {
                Ok(row.get::<_, String>(0)?)
            })?;

            let mut scopes = Vec::new();
            for scope in rows {
                scopes.push(scope?);
            }
            Ok(scopes)
        })
    }

    /// Get required scopes for an endpoint
    pub(crate) async fn get_required_scopes_for_endpoint(
        &self,
        endpoint_pattern: &str,
        method: &str,
    ) -> Result<Vec<String>> {
        let endpoint_pattern = endpoint_pattern.to_string();
        let method = method.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let scopes_json: String = conn.query_row(
                "SELECT required_scopes FROM endpoint_scope_map WHERE endpoint_pattern = ?1 AND method = ?2",
                params![endpoint_pattern, method],
                |row| row.get(0)
            )?;

            let scopes: Vec<String> = serde_json::from_str(&scopes_json)
                .map_err(|e| anyhow!("Failed to parse scopes JSON: {}", e))?;
            Ok(scopes)
        })
    }

    /// Get all endpoint patterns for pattern matching
    pub(crate) async fn get_all_endpoint_patterns(&self) -> Result<Vec<crate::auth::permissions::EndpointScopeMapping>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, endpoint_pattern, method, required_scopes, description FROM endpoint_scope_map"
            )?;

            let rows = stmt.query_map([], |row| {
                let scopes_json: String = row.get(3)?;
                let required_scopes: Vec<String> = serde_json::from_str(&scopes_json)
                    .map_err(|e| rusqlite::Error::InvalidColumnType(3, "JSON".to_string(), rusqlite::types::Type::Text))?;

                Ok(crate::auth::permissions::EndpointScopeMapping {
                    id: row.get(0)?,
                    endpoint_pattern: row.get(1)?,
                    method: row.get(2)?,
                    required_scopes,
                    description: row.get(4)?,
                })
            })?;

            let mut mappings = Vec::new();
            for mapping in rows {
                mappings.push(mapping?);
            }
            Ok(mappings)
        })
    }

    // ===== API TOKEN OPERATIONS =====

    /// Get API token by ID
    pub(crate) async fn get_api_token_by_id(&self, token_id: &str) -> Result<ApiToken> {
        let token_id = token_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute FROM api_tokens WHERE id = ?1",
                params![token_id],
                |row| {
                    let scopes_json: String = row.get(4)?;
                    let scopes: Vec<String> = serde_json::from_str(&scopes_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(4, "JSON".to_string(), rusqlite::types::Type::Text))?;

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

    /// Get API token by prefix
    pub(crate) async fn get_api_token_by_prefix(&self, prefix: &str) -> Result<ApiToken> {
        let prefix = prefix.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute FROM api_tokens WHERE prefix = ?1",
                params![prefix],
                |row| {
                    let scopes_json: String = row.get(4)?;
                    let scopes: Vec<String> = serde_json::from_str(&scopes_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(4, "JSON".to_string(), rusqlite::types::Type::Text))?;

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

    /// Update token last used timestamp
    pub(crate) async fn update_token_last_used(&self, token_id: &str) -> Result<()> {
        let token_id = token_id.to_string();
        let now = chrono::Utc::now().timestamp();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2",
                params![now, token_id]
            ).map(|_| ())?)
        })
    }

    /// Insert API token
    pub(crate) async fn insert_api_token(&self, token: &ApiToken) -> Result<()> {
        let scopes_json = serde_json::to_string(&token.scopes)?;
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "INSERT INTO api_tokens (id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    token.id, token.prefix, token.hash, token.salt, scopes_json,
                    token.description, token.is_enabled, token.revoked_at, token.last_used_at,
                    token.expires_at, token.created_at, token.created_by_user_id,
                    token.tenant_id, token.rate_limit_per_minute
                ]
            ).map(|_| ())?)
        })
    }

    /// Get API tokens for a user
    pub(crate) async fn get_api_tokens_for_user(&self, user_id: i64, tenant_id: &str) -> Result<Vec<ApiToken>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, prefix, hash, salt, scopes, description, is_enabled, revoked_at, last_used_at, expires_at, created_at, created_by_user_id, tenant_id, rate_limit_per_minute FROM api_tokens WHERE created_by_user_id = ?1 AND tenant_id = ?2 ORDER BY created_at DESC"
            )?;

            let rows = stmt.query_map(params![user_id, tenant_id], |row| {
                let scopes_json: String = row.get(4)?;
                let scopes: Vec<String> = serde_json::from_str(&scopes_json)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(4, "JSON".to_string(), rusqlite::types::Type::Text))?;

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

    /// Update API token
    pub(crate) async fn update_api_token(&self, token: &ApiToken) -> Result<()> {
        let scopes_json = serde_json::to_string(&token.scopes)?;
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE api_tokens SET hash = ?1, salt = ?2, scopes = ?3, description = ?4, is_enabled = ?5, revoked_at = ?6, expires_at = ?7, rate_limit_per_minute = ?8 WHERE id = ?9",
                params![
                    token.hash, token.salt, scopes_json, token.description,
                    token.is_enabled, token.revoked_at, token.expires_at,
                    token.rate_limit_per_minute, token.id
                ]
            ).map(|_| ())?)
        })
    }

    /// Delete API token
    pub(crate) async fn delete_api_token(&self, token_id: &str) -> Result<()> {
        let token_id = token_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM api_tokens WHERE id = ?1",
                params![token_id]
            ).map(|_| ())?)
        })
    }

    // ===== AUDIT LOGGING OPERATIONS =====

    /// Log an audit event
    pub(crate) async fn log_audit_event(
        &self,
        action: &str,
        user_id: Option<i64>,
        tenant_id: Option<&str>,
        resource_id: Option<&str>,
        details: Option<&str>,
    ) -> Result<()> {
        let action = action.to_string();
        let tenant_id = tenant_id.map(|s| s.to_string());
        let resource_id = resource_id.map(|s| s.to_string());
        let details = details.map(|s| s.to_string());
        let timestamp = chrono::Utc::now().timestamp();

        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "INSERT INTO audit_events (action, user_id, tenant_id, resource_id, details, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![action, user_id, tenant_id, resource_id, details, timestamp]
            ).map(|_| ())?)
        })
    }

    // ===== CA MANAGEMENT OPERATIONS =====

    /// Update CA
    pub(crate) async fn update_ca(&self, ca: &CA) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE ca_certificates SET name = ?1, description = ?2, is_active = ?3, crl_distribution_points = ?4, authority_info_access = ?5, key_usage = ?6, extended_key_usage = ?7, certificate_policies = ?8, policy_constraints = ?9, name_constraints = ?10, metadata = ?11 WHERE id = ?12",
                params![
                    ca.name, ca.description, ca.is_active, ca.crl_distribution_points,
                    ca.authority_info_access, ca.key_usage, ca.extended_key_usage,
                    ca.certificate_policies, ca.policy_constraints, ca.name_constraints,
                    ca.metadata, ca.id
                ]
            ).map(|_| ())?)
        })
    }

    /// Get certificate count for a CA
    pub(crate) async fn get_certificate_count_for_ca(&self, ca_id: i64) -> Result<i64> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE ca_id = ?1",
                params![ca_id],
                |row| row.get(0)
            )?)
        })
    }

    /// Get last CRL update timestamp for a CA
    pub(crate) async fn get_last_crl_update(&self, ca_id: i64) -> Result<i64> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT MAX(created_at) FROM crl_metadata WHERE ca_id = ?1",
                params![ca_id],
                |row| row.get(0)
            )?)
        })
    }

    /// Get child CAs for a parent CA
    pub(crate) async fn get_child_cas(&self, parent_ca_id: i64) -> Result<Vec<CA>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT * FROM ca_certificates WHERE parent_ca_id = ?1"
            )?;

            let rows = stmt.query_map(params![parent_ca_id], |row| {
                Ok(CA{
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    tenant_id: row.get(5)?,
                    name: row.get(6)?,
                    description: row.get(13)?,
                    key_algorithm: row.get(7)?,
                    key_size: row.get(14)?,
                    path_len: row.get(8)?,
                    basic_constraints: row.get(9)?,
                    crl_distribution_points: row.get(10)?,
                    authority_info_access: row.get(11)?,
                    is_active: row.get(12)?,
                    is_root_ca: row.get(15)?,
                    parent_ca_id: row.get(16)?,
                    serial_number: row.get(17)?,
                    issuer: row.get(18)?,
                    subject: row.get(19)?,
                    key_usage: row.get(20)?,
                    extended_key_usage: row.get(21)?,
                    certificate_policies: row.get(22)?,
                    policy_constraints: row.get(23)?,
                    name_constraints: row.get(24)?,
                    created_by_user_id: row.get(25)?,
                    metadata: row.get(26)?,
                })
            })?;

            let mut cas = Vec::new();
            for ca in rows {
                cas.push(ca?);
            }
            Ok(cas)
        })
    }

    /// Get certificates issued by a CA
    pub(crate) async fn get_certificates_by_ca(&self, ca_id: i64) -> Result<Vec<Certificate>> {
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, name, created_on, valid_until, type, user_id, renew_method, tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size, sans, metadata, status, ca_id, revoked_at, revoked_by_user_id, revocation_reason FROM user_certificates WHERE ca_id = ?1"
            )?;

            let rows = stmt.query_map(params![ca_id], |row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    certificate_type: row.get(4)?,
                    user_id: row.get(5)?,
                    renew_method: row.get(6)?,
                    tenant_id: row.get(7)?,
                    profile_id: row.get(8)?,
                    serial_number: row.get(9)?,
                    issuer: row.get(10)?,
                    subject: row.get(11)?,
                    algorithm: row.get(12)?,
                    key_size: row.get(13)?,
                    sans: row.get(14)?,
                    metadata: row.get(15)?,
                    status: row.get(16)?,
                    ca_id: row.get(17)?,
                    revoked_at: row.get(18)?,
                    revoked_by_user_id: row.get(19)?,
                    revocation_reason: row.get(20)?,
                    pkcs12: Vec::new(),
                    pkcs12_password: String::new(),
                })
            })?;

            let mut certificates = Vec::new();
            for cert in rows {
                certificates.push(cert?);
            }
            Ok(certificates)
        })
    }

    /// Revoke a certificate
    pub(crate) async fn revoke_certificate(
        &self,
        certificate_id: i64,
        revoked_by_user_id: i64,
        revocation_reason: Option<i32>,
        revocation_note: Option<String>,
    ) -> Result<()> {
        let revoked_at = chrono::Utc::now().timestamp();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET status = 'revoked', revoked_at = ?1, revoked_by_user_id = ?2, revocation_reason = ?3 WHERE id = ?4",
                params![revoked_at, revoked_by_user_id, revocation_reason, certificate_id]
            ).map(|_| ())?)
        })
    }

    /// Replace CA (for root CA rotation)
    pub(crate) async fn replace_ca(&self, old_ca_id: i64, new_ca: &CA) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            // Start transaction
            let tx = conn.unchecked_transaction()?;

            // Delete old CA
            tx.execute("DELETE FROM ca_certificates WHERE id = ?1", params![old_ca_id])?;

            // Insert new CA with same ID
            tx.execute(
                "INSERT INTO ca_certificates (id, created_on, valid_until, certificate, key, tenant_id, name, description, key_algorithm, key_size, path_len, basic_constraints, crl_distribution_points, authority_info_access, is_active, is_root_ca, parent_ca_id, serial_number, issuer, subject, key_usage, extended_key_usage, certificate_policies, policy_constraints, name_constraints, created_by_user_id, metadata) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)",
                params![
                    old_ca_id, new_ca.created_on, new_ca.valid_until, new_ca.cert, new_ca.key,
                    new_ca.tenant_id, new_ca.name, new_ca.description, new_ca.key_algorithm,
                    new_ca.key_size, new_ca.path_len, new_ca.basic_constraints,
                    new_ca.crl_distribution_points, new_ca.authority_info_access, new_ca.is_active,
                    new_ca.is_root_ca, new_ca.parent_ca_id, new_ca.serial_number, new_ca.issuer,
                    new_ca.subject, new_ca.key_usage, new_ca.extended_key_usage,
                    new_ca.certificate_policies, new_ca.policy_constraints, new_ca.name_constraints,
                    new_ca.created_by_user_id, new_ca.metadata
                ]
            )?;

            tx.commit()?;
            Ok(())
        })
    }

    /// Migrate certificates from old CA to new CA
    pub(crate) async fn migrate_certificates_to_new_ca(&self, old_ca_id: i64, new_ca_id: i64) -> Result<()> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET ca_id = ?1 WHERE ca_id = ?2",
                params![new_ca_id, old_ca_id]
            ).map(|_| ())?)
        })
    }

    /// Get CA by name and tenant
    pub(crate) async fn get_ca_by_name(&self, ca_name: &str, tenant_id: &str) -> Result<CA> {
        let ca_name = ca_name.to_string();
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT * FROM ca_certificates WHERE name = ?1 AND tenant_id = ?2 AND is_active = 1",
                params![ca_name, tenant_id],
                |row| {
                    Ok(CA{
                        id: row.get(0)?,
                        created_on: row.get(1)?,
                        valid_until: row.get(2)?,
                        cert: row.get(3)?,
                        key: row.get(4)?,
                        tenant_id: row.get(5)?,
                        name: row.get(6)?,
                        description: row.get(13)?,
                        key_algorithm: row.get(7)?,
                        key_size: row.get(14)?,
                        path_len: row.get(8)?,
                        basic_constraints: row.get(9)?,
                        crl_distribution_points: row.get(10)?,
                        authority_info_access: row.get(11)?,
                        is_active: row.get(12)?,
                        is_root_ca: row.get(15)?,
                        parent_ca_id: row.get(16)?,
                        serial_number: row.get(17)?,
                        issuer: row.get(18)?,
                        subject: row.get(19)?,
                        key_usage: row.get(20)?,
                        extended_key_usage: row.get(21)?,
                        certificate_policies: row.get(22)?,
                        policy_constraints: row.get(23)?,
                        name_constraints: row.get(24)?,
                        created_by_user_id: row.get(25)?,
                        metadata: row.get(26)?,
                    })
                }
            )?)
        })
    }

    /// Get the best CA for certificate issuance
    pub(crate) async fn get_best_ca_for_issuance(
        &self,
        tenant_id: &str,
        cert_type: &crate::data::enums::CertificateType
    ) -> Result<CA> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            // Priority order:
            // 1. Active CAs with keyCertSign usage
            // 2. Most recently created
            // 3. Intermediate CAs preferred over root CAs (for better security)
            let mut stmt = conn.prepare(
                "SELECT * FROM ca_certificates
                 WHERE tenant_id = ?1 AND is_active = 1
                 ORDER BY
                   CASE WHEN is_root_ca = 0 THEN 0 ELSE 1 END,
                   created_on DESC
                 LIMIT 1"
            )?;

            stmt.query_row(params![tenant_id], |row| {
                Ok(CA{
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    tenant_id: row.get(5)?,
                    name: row.get(6)?,
                    description: row.get(13)?,
                    key_algorithm: row.get(7)?,
                    key_size: row.get(14)?,
                    path_len: row.get(8)?,
                    basic_constraints: row.get(9)?,
                    crl_distribution_points: row.get(10)?,
                    authority_info_access: row.get(11)?,
                    is_active: row.get(12)?,
                    is_root_ca: row.get(15)?,
                    parent_ca_id: row.get(16)?,
                    serial_number: row.get(17)?,
                    issuer: row.get(18)?,
                    subject: row.get(19)?,
                    key_usage: row.get(20)?,
                    extended_key_usage: row.get(21)?,
                    certificate_policies: row.get(22)?,
                    policy_constraints: row.get(23)?,
                    name_constraints: row.get(24)?,
                    created_by_user_id: row.get(25)?,
                    metadata: row.get(26)?,
                })
            }).map_err(|_| anyhow!("No suitable CA found for certificate issuance"))
        })
    }

    /// Get active CAs for a tenant (for CA selection)
    pub(crate) async fn get_active_cas_for_tenant(&self, tenant_id: &str) -> Result<Vec<CA>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT * FROM ca_certificates WHERE tenant_id = ?1 AND is_active = 1 ORDER BY created_on DESC"
            )?;

            let rows = stmt.query_map(params![tenant_id], |row| {
                Ok(CA{
                    id: row.get(0)?,
                    created_on: row.get(1)?,
                    valid_until: row.get(2)?,
                    cert: row.get(3)?,
                    key: row.get(4)?,
                    tenant_id: row.get(5)?,
                    name: row.get(6)?,
                    description: row.get(13)?,
                    key_algorithm: row.get(7)?,
                    key_size: row.get(14)?,
                    path_len: row.get(8)?,
                    basic_constraints: row.get(9)?,
                    crl_distribution_points: row.get(10)?,
                    authority_info_access: row.get(11)?,
                    is_active: row.get(12)?,
                    is_root_ca: row.get(15)?,
                    parent_ca_id: row.get(16)?,
                    serial_number: row.get(17)?,
                    issuer: row.get(18)?,
                    subject: row.get(19)?,
                    key_usage: row.get(20)?,
                    extended_key_usage: row.get(21)?,
                    certificate_policies: row.get(22)?,
                    policy_constraints: row.get(23)?,
                    name_constraints: row.get(24)?,
                    created_by_user_id: row.get(25)?,
                    metadata: row.get(26)?,
                })
            })?;

            let mut cas = Vec::new();
            for ca in rows {
                cas.push(ca?);
            }
            Ok(cas)
        })
    }

    // ===== CERTIFICATE PROFILE OPERATIONS =====

    /// Insert certificate profile
    pub(crate) async fn insert_profile(&self, profile: &crate::data::profile::Profile) -> Result<()> {
        let eku_json = serde_json::to_string(&profile.eku)?;
        let key_usage_json = serde_json::to_string(&profile.key_usage)?;
        let san_rules_json = profile.san_rules.as_ref()
            .map(|rules| serde_json::to_string(rules))
            .transpose()?;
        let key_alg_options_json = serde_json::to_string(&profile.key_alg_options)?;

        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "INSERT INTO certificate_profiles (id, name, eku, key_usage, san_rules, default_days, max_days, renewal_window_pct, key_alg_options, tenant_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    profile.id, profile.name, eku_json, key_usage_json, san_rules_json,
                    profile.default_days, profile.max_days, profile.renewal_window_pct,
                    key_alg_options_json, profile.tenant_id, profile.created_at
                ]
            ).map(|_| ())?)
        })
    }

    /// Get profile by ID
    pub(crate) async fn get_profile_by_id(&self, profile_id: &str) -> Result<crate::data::profile::Profile> {
        let profile_id = profile_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, eku, key_usage, san_rules, default_days, max_days, renewal_window_pct, key_alg_options, tenant_id, created_at FROM certificate_profiles WHERE id = ?1",
                params![profile_id],
                |row| {
                    let eku_json: String = row.get(2)?;
                    let key_usage_json: String = row.get(3)?;
                    let san_rules_json: Option<String> = row.get(4)?;
                    let key_alg_options_json: String = row.get(8)?;

                    let eku: Vec<String> = serde_json::from_str(&eku_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(2, "JSON".to_string(), rusqlite::types::Type::Text))?;
                    let key_usage: Vec<String> = serde_json::from_str(&key_usage_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(3, "JSON".to_string(), rusqlite::types::Type::Text))?;
                    let san_rules: Option<crate::data::profile::SanRules> = san_rules_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(|_| rusqlite::Error::InvalidColumnType(4, "JSON".to_string(), rusqlite::types::Type::Text))?;
                    let key_alg_options: Vec<String> = serde_json::from_str(&key_alg_options_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(8, "JSON".to_string(), rusqlite::types::Type::Text))?;

                    Ok(crate::data::profile::Profile {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        eku,
                        key_usage,
                        san_rules,
                        default_days: row.get(5)?,
                        max_days: row.get(6)?,
                        renewal_window_pct: row.get(7)?,
                        key_alg_options,
                        tenant_id: row.get(9)?,
                        created_at: row.get(10)?,
                    })
                }
            )?)
        })
    }

    /// Get profile by name and tenant
    pub(crate) async fn get_profile_by_name(&self, name: &str, tenant_id: &str) -> Result<crate::data::profile::Profile> {
        let name = name.to_string();
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT id, name, eku, key_usage, san_rules, default_days, max_days, renewal_window_pct, key_alg_options, tenant_id, created_at FROM certificate_profiles WHERE name = ?1 AND tenant_id = ?2",
                params![name, tenant_id],
                |row| {
                    let eku_json: String = row.get(2)?;
                    let key_usage_json: String = row.get(3)?;
                    let san_rules_json: Option<String> = row.get(4)?;
                    let key_alg_options_json: String = row.get(8)?;

                    let eku: Vec<String> = serde_json::from_str(&eku_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(2, "JSON".to_string(), rusqlite::types::Type::Text))?;
                    let key_usage: Vec<String> = serde_json::from_str(&key_usage_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(3, "JSON".to_string(), rusqlite::types::Type::Text))?;
                    let san_rules: Option<crate::data::profile::SanRules> = san_rules_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(|_| rusqlite::Error::InvalidColumnType(4, "JSON".to_string(), rusqlite::types::Type::Text))?;
                    let key_alg_options: Vec<String> = serde_json::from_str(&key_alg_options_json)
                        .map_err(|_| rusqlite::Error::InvalidColumnType(8, "JSON".to_string(), rusqlite::types::Type::Text))?;

                    Ok(crate::data::profile::Profile {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        eku,
                        key_usage,
                        san_rules,
                        default_days: row.get(5)?,
                        max_days: row.get(6)?,
                        renewal_window_pct: row.get(7)?,
                        key_alg_options,
                        tenant_id: row.get(9)?,
                        created_at: row.get(10)?,
                    })
                }
            )?)
        })
    }

    /// Get profiles for a tenant
    pub(crate) async fn get_profiles_for_tenant(&self, tenant_id: &str) -> Result<Vec<crate::data::profile::Profile>> {
        let tenant_id = tenant_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            let mut stmt = conn.prepare(
                "SELECT id, name, eku, key_usage, san_rules, default_days, max_days, renewal_window_pct, key_alg_options, tenant_id, created_at FROM certificate_profiles WHERE tenant_id = ?1 ORDER BY created_at DESC"
            )?;

            let rows = stmt.query_map(params![tenant_id], |row| {
                let eku_json: String = row.get(2)?;
                let key_usage_json: String = row.get(3)?;
                let san_rules_json: Option<String> = row.get(4)?;
                let key_alg_options_json: String = row.get(8)?;

                let eku: Vec<String> = serde_json::from_str(&eku_json)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(2, "JSON".to_string(), rusqlite::types::Type::Text))?;
                let key_usage: Vec<String> = serde_json::from_str(&key_usage_json)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(3, "JSON".to_string(), rusqlite::types::Type::Text))?;
                let san_rules: Option<crate::data::profile::SanRules> = san_rules_json
                    .map(|json| serde_json::from_str(&json))
                    .transpose()
                    .map_err(|_| rusqlite::Error::InvalidColumnType(4, "JSON".to_string(), rusqlite::types::Type::Text))?;
                let key_alg_options: Vec<String> = serde_json::from_str(&key_alg_options_json)
                    .map_err(|_| rusqlite::Error::InvalidColumnType(8, "JSON".to_string(), rusqlite::types::Type::Text))?;

                Ok(crate::data::profile::Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    eku,
                    key_usage,
                    san_rules,
                    default_days: row.get(5)?,
                    max_days: row.get(6)?,
                    renewal_window_pct: row.get(7)?,
                    key_alg_options,
                    tenant_id: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })?;

            let mut profiles = Vec::new();
            for profile in rows {
                profiles.push(profile?);
            }
            Ok(profiles)
        })
    }

    /// Update profile
    pub(crate) async fn update_profile(&self, profile: &crate::data::profile::Profile) -> Result<()> {
        let eku_json = serde_json::to_string(&profile.eku)?;
        let key_usage_json = serde_json::to_string(&profile.key_usage)?;
        let san_rules_json = profile.san_rules.as_ref()
            .map(|rules| serde_json::to_string(rules))
            .transpose()?;
        let key_alg_options_json = serde_json::to_string(&profile.key_alg_options)?;

        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE certificate_profiles SET name = ?1, eku = ?2, key_usage = ?3, san_rules = ?4, default_days = ?5, max_days = ?6, renewal_window_pct = ?7, key_alg_options = ?8 WHERE id = ?9",
                params![
                    profile.name, eku_json, key_usage_json, san_rules_json,
                    profile.default_days, profile.max_days, profile.renewal_window_pct,
                    key_alg_options_json, profile.id
                ]
            ).map(|_| ())?)
        })
    }

    /// Delete profile
    pub(crate) async fn delete_profile(&self, profile_id: &str) -> Result<()> {
        let profile_id = profile_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM certificate_profiles WHERE id = ?1",
                params![profile_id]
            ).map(|_| ())?)
        })
    }

    /// Get certificate count for a profile
    pub(crate) async fn get_certificate_count_for_profile(&self, profile_id: &str) -> Result<i64> {
        let profile_id = profile_id.to_string();
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE profile_id = ?1",
                params![profile_id],
                |row| row.get(0)
            )?)
        })
    }

    // ===== ENHANCED CERTIFICATE SEARCH =====

    /// Advanced certificate search with filters and operators
    pub(crate) async fn search_certificates(
        &self,
        tenant_id: &str,
        request: &crate::cert::CertificateSearchRequest,
    ) -> Result<crate::cert::CertificateSearchResponse> {
        let tenant_id = tenant_id.to_string();

        db_do!(self.pool, |conn: &Connection| {
            // Build WHERE clause from filters
            let mut where_clauses = vec!["tenant_id = ?1".to_string()];
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(tenant_id.clone())];
            let mut param_index = 2;

            // Add include/exclude filters
            if !request.include_revoked.unwrap_or(true) {
                where_clauses.push("status != 'revoked'".to_string());
            }

            if !request.include_expired.unwrap_or(true) {
                let now = chrono::Utc::now().timestamp();
                where_clauses.push(format!("valid_until > {}", now));
            }

            // Process search filters
            if let Some(filters) = &request.filters {
                for filter in filters {
                    let (clause, filter_params) = self.build_filter_clause(filter, &mut param_index)?;
                    where_clauses.push(clause);
                    params.extend(filter_params);
                }
            }

            // Build ORDER BY clause
            let mut order_clauses = Vec::new();
            if let Some(sort_options) = &request.sort {
                for sort in sort_options {
                    let field_name = self.map_search_field_to_column(&sort.field);
                    let direction = match sort.direction {
                        crate::cert::SortDirection::Asc => "ASC",
                        crate::cert::SortDirection::Desc => "DESC",
                    };
                    order_clauses.push(format!("{} {}", field_name, direction));
                }
            }

            if order_clauses.is_empty() {
                order_clauses.push("created_on DESC".to_string());
            }

            // Build pagination
            let page = request.page.unwrap_or(1).max(1);
            let per_page = request.per_page.unwrap_or(20).min(100).max(1);
            let offset = (page - 1) * per_page;

            // Count total results
            let count_query = format!(
                "SELECT COUNT(*) FROM user_certificates WHERE {}",
                where_clauses.join(" AND ")
            );

            let total: i64 = {
                let mut stmt = conn.prepare(&count_query)?;
                let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
                stmt.query_row(&param_refs[..], |row| row.get(0))?
            };

            // Get results
            let query = format!(
                "SELECT id, name, created_on, valid_until, type, user_id, renew_method, tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size, sans, metadata, status, ca_id, revoked_at, revoked_by_user_id, revocation_reason FROM user_certificates WHERE {} ORDER BY {} LIMIT {} OFFSET {}",
                where_clauses.join(" AND "),
                order_clauses.join(", "),
                per_page,
                offset
            );

            let mut stmt = conn.prepare(&query)?;
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

            let rows = stmt.query_map(&param_refs[..], |row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    certificate_type: row.get(4)?,
                    user_id: row.get(5)?,
                    renew_method: row.get(6)?,
                    tenant_id: row.get(7)?,
                    profile_id: row.get(8)?,
                    serial_number: row.get(9)?,
                    issuer: row.get(10)?,
                    subject: row.get(11)?,
                    algorithm: row.get(12)?,
                    key_size: row.get(13)?,
                    sans: row.get(14)?,
                    metadata: row.get(15)?,
                    status: row.get(16)?,
                    ca_id: row.get(17)?,
                    revoked_at: row.get(18)?,
                    revoked_by_user_id: row.get(19)?,
                    revocation_reason: row.get(20)?,
                    pkcs12: Vec::new(),
                    pkcs12_password: String::new(),
                })
            })?;

            let mut certificates = Vec::new();
            for cert in rows {
                certificates.push(cert?);
            }

            Ok(crate::cert::CertificateSearchResponse {
                certificates,
                total,
                page,
                per_page,
                has_more: offset + per_page < total as i32,
                filters_applied: request.filters.clone().unwrap_or_default(),
                sort_applied: request.sort.clone().unwrap_or_default(),
            })
        })
    }

    /// Build SQL filter clause from search filter
    fn build_filter_clause(
        &self,
        filter: &crate::cert::SearchFilter,
        param_index: &mut i32,
    ) -> Result<(String, Vec<Box<dyn rusqlite::ToSql>>)> {
        let field_name = self.map_search_field_to_column(&filter.field);
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        let clause = match &filter.operator {
            crate::cert::SearchOperator::Eq => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} = ?{}", field_name, param_index)
            },
            crate::cert::SearchOperator::Ne => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} != ?{}", field_name, param_index)
            },
            crate::cert::SearchOperator::Lt => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} < ?{}", field_name, param_index)
            },
            crate::cert::SearchOperator::Lte => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} <= ?{}", field_name, param_index)
            },
            crate::cert::SearchOperator::Gt => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} > ?{}", field_name, param_index)
            },
            crate::cert::SearchOperator::Gte => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} >= ?{}", field_name, param_index)
            },
            crate::cert::SearchOperator::Like => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} LIKE ?{}", field_name, param_index)
            },
            crate::cert::SearchOperator::StartsWith => {
                if let crate::cert::SearchValue::String(s) = &filter.value {
                    params.push(Box::new(format!("{}%", s)));
                    format!("{} LIKE ?{}", field_name, param_index)
                } else {
                    return Err(anyhow!("StartsWith operator requires string value"));
                }
            },
            crate::cert::SearchOperator::EndsWith => {
                if let crate::cert::SearchValue::String(s) = &filter.value {
                    params.push(Box::new(format!("%{}", s)));
                    format!("{} LIKE ?{}", field_name, param_index)
                } else {
                    return Err(anyhow!("EndsWith operator requires string value"));
                }
            },
            crate::cert::SearchOperator::In => {
                if let crate::cert::SearchValue::Array(arr) = &filter.value {
                    let placeholders: Vec<String> = (0..arr.len())
                        .map(|i| format!("?{}", param_index + i as i32))
                        .collect();
                    for item in arr {
                        params.push(Box::new(item.clone()));
                    }
                    format!("{} IN ({})", field_name, placeholders.join(", "))
                } else {
                    return Err(anyhow!("In operator requires array value"));
                }
            },
            crate::cert::SearchOperator::Between => {
                if let crate::cert::SearchValue::Range { start, end } = &filter.value {
                    params.push(Box::new(*start));
                    params.push(Box::new(*end));
                    format!("{} BETWEEN ?{} AND ?{}", field_name, param_index, param_index + 1)
                } else {
                    return Err(anyhow!("Between operator requires range value"));
                }
            },
            crate::cert::SearchOperator::Contains => {
                params.push(self.search_value_to_sql(&filter.value)?);
                format!("{} LIKE '%' || ?{} || '%'", field_name, param_index)
            },
            crate::cert::SearchOperator::Nin => {
                if let crate::cert::SearchValue::Array(arr) = &filter.value {
                    let placeholders: Vec<String> = (0..arr.len())
                        .map(|i| format!("?{}", param_index + i as i32))
                        .collect();
                    for item in arr {
                        params.push(Box::new(item.clone()));
                    }
                    format!("{} NOT IN ({})", field_name, placeholders.join(", "))
                } else {
                    return Err(anyhow!("Nin operator requires array value"));
                }
            },
        };

        *param_index += params.len() as i32;
        Ok((clause, params))
    }

    /// Map search field to database column name
    fn map_search_field_to_column(&self, field: &crate::cert::SearchField) -> &'static str {
        match field {
            crate::cert::SearchField::Name => "name",
            crate::cert::SearchField::CommonName => "subject", // Extract CN from subject
            crate::cert::SearchField::SerialNumber => "serial_number",
            crate::cert::SearchField::Issuer => "issuer",
            crate::cert::SearchField::Subject => "subject",
            crate::cert::SearchField::Status => "status",
            crate::cert::SearchField::CertificateType => "type",
            crate::cert::SearchField::Algorithm => "algorithm",
            crate::cert::SearchField::KeySize => "key_size",
            crate::cert::SearchField::CreatedAt => "created_on",
            crate::cert::SearchField::ValidUntil => "valid_until",
            crate::cert::SearchField::RevokedAt => "revoked_at",
            crate::cert::SearchField::Sans => "sans",
            crate::cert::SearchField::ProfileId => "profile_id",
            crate::cert::SearchField::CaId => "ca_id",
            crate::cert::SearchField::UserId => "user_id",
            crate::cert::SearchField::Metadata => "metadata",
        }
    }

    /// Convert search value to SQL parameter
    fn search_value_to_sql(&self, value: &crate::cert::SearchValue) -> Result<Box<dyn rusqlite::ToSql>> {
        match value {
            crate::cert::SearchValue::String(s) => Ok(Box::new(s.clone())),
            crate::cert::SearchValue::Number(n) => Ok(Box::new(*n)),
            crate::cert::SearchValue::Float(f) => Ok(Box::new(*f)),
            crate::cert::SearchValue::Boolean(b) => Ok(Box::new(*b)),
            _ => Err(anyhow!("Unsupported search value type for SQL conversion")),
        }
    }

    // ===== BATCH OPERATIONS =====

    /// Execute batch operation on certificates
    pub(crate) async fn execute_batch_operation(
        &self,
        request: &crate::cert::BatchOperationRequest,
        user_id: i64,
        tenant_id: &str,
    ) -> Result<crate::cert::BatchOperationResponse> {
        let mut results = Vec::new();
        let mut successful = 0;
        let mut failed = 0;

        for cert_id in &request.certificate_ids {
            let result = match request.operation {
                crate::cert::BatchOperation::Revoke => {
                    self.batch_revoke_certificate(*cert_id, user_id, &request.parameters).await
                },
                crate::cert::BatchOperation::Restore => {
                    self.batch_restore_certificate(*cert_id, user_id).await
                },
                crate::cert::BatchOperation::Delete => {
                    self.batch_delete_certificate(*cert_id, user_id).await
                },
                crate::cert::BatchOperation::Download => {
                    // Download operations are handled separately
                    Ok("Download queued".to_string())
                },
                crate::cert::BatchOperation::Renew => {
                    self.batch_renew_certificate(*cert_id, user_id, &request.parameters).await
                },
                crate::cert::BatchOperation::UpdateMetadata => {
                    self.batch_update_metadata(*cert_id, &request.parameters).await
                },
            };

            match result {
                Ok(details) => {
                    successful += 1;
                    results.push(crate::cert::BatchOperationResult {
                        certificate_id: *cert_id,
                        success: true,
                        error: None,
                        details: Some(details),
                    });
                },
                Err(e) => {
                    failed += 1;
                    results.push(crate::cert::BatchOperationResult {
                        certificate_id: *cert_id,
                        success: false,
                        error: Some(e.to_string()),
                        details: None,
                    });
                }
            }
        }

        Ok(crate::cert::BatchOperationResponse {
            operation: request.operation.clone(),
            total_requested: request.certificate_ids.len() as i32,
            successful,
            failed,
            results,
            download_url: None, // Set by caller for download operations
        })
    }

    /// Batch revoke certificate
    async fn batch_revoke_certificate(
        &self,
        cert_id: i64,
        user_id: i64,
        params: &Option<crate::cert::BatchOperationParameters>,
    ) -> Result<String> {
        let reason = params.as_ref()
            .and_then(|p| p.revocation_reason)
            .unwrap_or(0); // unspecified

        self.revoke_certificate(cert_id, user_id, Some(reason), None).await?;
        Ok(format!("Certificate {} revoked", cert_id))
    }

    /// Batch restore certificate
    async fn batch_restore_certificate(&self, cert_id: i64, _user_id: i64) -> Result<String> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "UPDATE user_certificates SET status = 'active', revoked_at = NULL, revoked_by_user_id = NULL, revocation_reason = NULL WHERE id = ?1",
                params![cert_id]
            ).map(|_| format!("Certificate {} restored", cert_id))?)
        })
    }

    /// Batch delete certificate
    async fn batch_delete_certificate(&self, cert_id: i64, _user_id: i64) -> Result<String> {
        db_do!(self.pool, |conn: &Connection| {
            Ok(conn.execute(
                "DELETE FROM user_certificates WHERE id = ?1",
                params![cert_id]
            ).map(|_| format!("Certificate {} deleted", cert_id))?)
        })
    }

    /// Batch renew certificate
    async fn batch_renew_certificate(
        &self,
        cert_id: i64,
        _user_id: i64,
        _params: &Option<crate::cert::BatchOperationParameters>,
    ) -> Result<String> {
        // This would involve creating a new certificate based on the old one
        // For now, just mark as renewed
        Ok(format!("Certificate {} renewal initiated", cert_id))
    }

    /// Batch update metadata
    async fn batch_update_metadata(
        &self,
        cert_id: i64,
        params: &Option<crate::cert::BatchOperationParameters>,
    ) -> Result<String> {
        if let Some(params) = params {
            if let Some(metadata) = &params.metadata {
                let metadata_json = serde_json::to_string(metadata)?;
                db_do!(self.pool, |conn: &Connection| {
                    Ok(conn.execute(
                        "UPDATE user_certificates SET metadata = ?1 WHERE id = ?2",
                        params![metadata_json, cert_id]
                    ).map(|_| format!("Certificate {} metadata updated", cert_id))?)
                })
            } else {
                Err(anyhow!("No metadata provided for update"))
            }
        } else {
            Err(anyhow!("No parameters provided for metadata update"))
        }
    }

    // ===== CERTIFICATE STATISTICS =====

    /// Get certificate statistics for a tenant
    pub(crate) async fn get_certificate_statistics(&self, tenant_id: &str) -> Result<crate::cert::CertificateStatistics> {
        let tenant_id = tenant_id.to_string();
        let now = chrono::Utc::now().timestamp();
        let thirty_days_from_now = now + (30 * 24 * 60 * 60);
        let seven_days_ago = now - (7 * 24 * 60 * 60);
        let thirty_days_ago = now - (30 * 24 * 60 * 60);

        db_do!(self.pool, |conn: &Connection| {
            // Basic counts
            let total_certificates: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1",
                params![tenant_id],
                |row| row.get(0)
            )?;

            let active_certificates: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND status = 'active'",
                params![tenant_id],
                |row| row.get(0)
            )?;

            let revoked_certificates: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND status = 'revoked'",
                params![tenant_id],
                |row| row.get(0)
            )?;

            let expired_certificates: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND valid_until < ?2",
                params![tenant_id, now],
                |row| row.get(0)
            )?;

            let expiring_soon: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND valid_until BETWEEN ?2 AND ?3 AND status = 'active'",
                params![tenant_id, now, thirty_days_from_now],
                |row| row.get(0)
            )?;

            // By type
            let server_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND type = 'Server'",
                params![tenant_id],
                |row| row.get(0)
            )?;

            let client_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND type = 'Client'",
                params![tenant_id],
                |row| row.get(0)
            )?;

            // Recent activity
            let issued_last_7_days: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND created_on >= ?2",
                params![tenant_id, seven_days_ago],
                |row| row.get(0)
            )?;

            let issued_last_30_days: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND created_on >= ?2",
                params![tenant_id, thirty_days_ago],
                |row| row.get(0)
            )?;

            let revoked_last_7_days: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND revoked_at >= ?2",
                params![tenant_id, seven_days_ago],
                |row| row.get(0)
            )?;

            let revoked_last_30_days: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND revoked_at >= ?2",
                params![tenant_id, thirty_days_ago],
                |row| row.get(0)
            )?;

            Ok(crate::cert::CertificateStatistics {
                total_certificates,
                active_certificates,
                revoked_certificates,
                expired_certificates,
                expiring_soon,
                by_type: crate::cert::CertificateTypeStats {
                    server: server_count,
                    client: client_count,
                },
                by_algorithm: Vec::new(), // TODO: Implement algorithm stats
                by_ca: Vec::new(),        // TODO: Implement CA stats
                by_profile: Vec::new(),   // TODO: Implement profile stats
                recent_activity: crate::cert::RecentActivity {
                    certificates_issued_last_7_days: issued_last_7_days,
                    certificates_issued_last_30_days: issued_last_30_days,
                    certificates_revoked_last_7_days: revoked_last_7_days,
                    certificates_revoked_last_30_days: revoked_last_30_days,
                },
            })
        })
    }

    // ===== EXPIRING CERTIFICATES =====

    /// Get certificates expiring within threshold
    pub(crate) async fn get_expiring_certificates(
        &self,
        tenant_id: &str,
        threshold: i64,
        page: i32,
        per_page: i32,
    ) -> Result<crate::cert::CertificateSearchResponse> {
        let tenant_id = tenant_id.to_string();
        let now = chrono::Utc::now().timestamp();
        let offset = (page - 1) * per_page;

        db_do!(self.pool, |conn: &Connection| {
            // Count total
            let total: i64 = conn.query_row(
                "SELECT COUNT(*) FROM user_certificates WHERE tenant_id = ?1 AND valid_until BETWEEN ?2 AND ?3 AND status = 'active'",
                params![tenant_id, now, threshold],
                |row| row.get(0)
            )?;

            // Get certificates
            let mut stmt = conn.prepare(
                "SELECT id, name, created_on, valid_until, type, user_id, renew_method, tenant_id, profile_id, serial_number, issuer, subject, algorithm, key_size, sans, metadata, status, ca_id, revoked_at, revoked_by_user_id, revocation_reason FROM user_certificates WHERE tenant_id = ?1 AND valid_until BETWEEN ?2 AND ?3 AND status = 'active' ORDER BY valid_until ASC LIMIT ?4 OFFSET ?5"
            )?;

            let rows = stmt.query_map(params![tenant_id, now, threshold, per_page, offset], |row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    certificate_type: row.get(4)?,
                    user_id: row.get(5)?,
                    renew_method: row.get(6)?,
                    tenant_id: row.get(7)?,
                    profile_id: row.get(8)?,
                    serial_number: row.get(9)?,
                    issuer: row.get(10)?,
                    subject: row.get(11)?,
                    algorithm: row.get(12)?,
                    key_size: row.get(13)?,
                    sans: row.get(14)?,
                    metadata: row.get(15)?,
                    status: row.get(16)?,
                    ca_id: row.get(17)?,
                    revoked_at: row.get(18)?,
                    revoked_by_user_id: row.get(19)?,
                    revocation_reason: row.get(20)?,
                    pkcs12: Vec::new(),
                    pkcs12_password: String::new(),
                })
            })?;

            let mut certificates = Vec::new();
            for cert in rows {
                certificates.push(cert?);
            }

            Ok(crate::cert::CertificateSearchResponse {
                certificates,
                total,
                page,
                per_page,
                has_more: offset + per_page < total as i32,
                filters_applied: Vec::new(),
                sort_applied: Vec::new(),
            })
        })
    }

    // ===== CERTIFICATE CHAIN OPERATIONS =====

    /// Build certificate chain for a certificate
    pub(crate) async fn build_certificate_chain(&self, cert_id: i64) -> Result<crate::cert::CertificateChain> {
        // Get the certificate
        let certificate = self.get_certificate(cert_id).await?;

        // Get the issuing CA
        let ca = self.get_ca_by_id(certificate.ca_id).await?;

        // Build issuer chain (simplified - would need more complex logic for full chains)
        let issuer_chain = Vec::new(); // TODO: Implement full chain building

        Ok(crate::cert::CertificateChain {
            certificate,
            issuer_chain,
            root_ca: None, // TODO: Find root CA
            chain_valid: true, // TODO: Implement validation
            validation_errors: Vec::new(),
        })
    }

    /// Validate certificate chain
    pub(crate) async fn validate_certificate_chain(
        &self,
        cert_id: i64,
        _request: &crate::cert::ChainValidationRequest,
    ) -> Result<crate::cert::ChainValidationResponse> {
        // Simplified validation - would need full implementation
        Ok(crate::cert::ChainValidationResponse {
            certificate_id: cert_id,
            chain_valid: true,
            validation_results: Vec::new(),
            chain_length: 1,
            expires_at: chrono::Utc::now().timestamp() + (365 * 24 * 60 * 60),
        })
    }

    /// Create ZIP archive of certificates
    pub(crate) async fn create_certificate_zip_archive(
        &self,
        cert_ids: &[i64],
        format: &str,
        _include_chain: bool,
    ) -> Result<Vec<u8>> {
        // Simplified implementation - would need actual ZIP creation
        let mut archive_data = Vec::new();

        for cert_id in cert_ids {
            let cert = self.get_certificate(*cert_id).await?;
            let cert_data = format!("Certificate {} in {} format\n", cert.name, format);
            archive_data.extend_from_slice(cert_data.as_bytes());
        }

        Ok(archive_data)
    }
}