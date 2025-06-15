use std::fs;
use std::os::unix::fs::PermissionsExt;
use rusqlite::fallible_iterator::FallibleIterator;
use std::path::Path;
use std::str::FromStr;
use argon2::password_hash::PasswordHashString;
use rusqlite::{params, Connection, Result};
use crate::{ApiError, Certificate, User};
use crate::data::enums::UserRole;

pub(crate) struct VaulTLSDB {
    connection: Connection
}

impl VaulTLSDB {
    pub(crate) fn new(db_path: &Path) -> Result<Self> {
        let connection = Connection::open(db_path)?;
        connection.execute("PRAGMA foreign_keys = ON", [])?;

        let mut perms = fs::metadata(db_path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(db_path, perms).unwrap();

        Ok(Self { connection })
    }

    /// Initialize the database with the required tables
    pub(crate) fn initialize_db(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.connection.execute(
            "CREATE TABLE ca_certificates (
                id INTEGER PRIMARY KEY,
                created_on INTEGER NOT NULL,
                valid_until INTEGER NOT NULL,
                certificate BLOB,
                key BLOB
            )",
            [],
        )?;

        self.connection.execute(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT,
                oidc_id TEXT,
                role INTEGER NOT NULL
            )",
            []
        )?;

        self.connection.execute(
            "CREATE TABLE user_certificates (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                created_on INTEGER NOT NULL,
                valid_until INTEGER NOT NULL,
                pkcs12 BLOB,
                ca_id INTEGER,
                user_id INTEGER,
                subject_alt_name TEXT,
                FOREIGN KEY(ca_id) REFERENCES ca_certificates(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
            [],
        )?;

        Ok(())
    }    

    /// Insert a new CA certificate into the database
    /// Adds id to the Certificate struct
    pub(crate) fn insert_ca(
        &self,
        ca: &mut Certificate
    ) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "INSERT INTO ca_certificates (created_on, valid_until, certificate, key) VALUES (?1, ?2, ?3, ?4)",
            params![ca.created_on, ca.valid_until, ca.cert, ca.key],
        )?;
        
        ca.ca_id = self.connection.last_insert_rowid();

        Ok(())
    }

    /// Retrieve the most recent CA entry from the database
    pub(crate) fn get_current_ca(&self) -> Result<Certificate, rusqlite::Error> {
        let mut stmt = self.connection.prepare("SELECT * FROM ca_certificates ORDER BY id DESC LIMIT 1")?;

        stmt.query_row([], |row| {
            Ok(Certificate{
                id: row.get(0)?,
                created_on: row.get(1)?,
                valid_until: row.get(2)?,
                cert: row.get(3)?,
                key: row.get(4)?,
                ..Default::default()
            })
        })
    }

    /// Retrieve all user certificates from the database
    /// If user_id is Some, only certificates for that user are returned
    /// If user_id is None, all certificates are returned
    pub(crate) fn get_all_user_cert(&self, user_id: Option<i64>) -> Result<Vec<Certificate>, rusqlite::Error>{
        let query = match user_id {
            Some(_) => "SELECT id, name, created_on, valid_until, pkcs12, user_id, subject_alt_name FROM user_certificates WHERE user_id = ?1",
            None => "SELECT id, name, created_on, valid_until, pkcs12, user_id, subject_alt_name FROM user_certificates"
        };
        let mut stmt = self.connection.prepare(query)?;
        let rows = match user_id {
            Some(id) => stmt.query(params![id])?,
            None => stmt.query([])?,
        };
        rows.map(|row| {
                Ok(Certificate {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_on: row.get(2)?,
                    valid_until: row.get(3)?,
                    pkcs12: row.get(4)?,
                    user_id: row.get(5)?,
                    subject_alt_name: row.get(6)?,
                    ..Default::default()
                })
            })
            .collect()
    }

    /// Retrieve the certificate's PKCS12 data with id from the database
    /// Returns the id of the user the certificate belongs to and the PKCS12 data
    pub(crate) fn get_user_cert_pkcs12(&self, id: i64) -> Result<(i64, Vec<u8>), rusqlite::Error> {
        let mut stmt = self.connection.prepare("SELECT user_id, pkcs12 FROM user_certificates WHERE id = ?1")?;

        stmt.query_row(
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
    }

    /// Insert a new certificate into the database
    /// Adds id to Certificate struct
    pub(crate) fn insert_user_cert(&self, cert: &mut Certificate) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "INSERT INTO user_certificates (name, created_on, valid_until, pkcs12, ca_id, user_id, subject_alt_name) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![cert.name, cert.created_on, cert.valid_until, cert.pkcs12, cert.ca_id, cert.user_id, cert.subject_alt_name],
        )?;
        
        cert.id = self.connection.last_insert_rowid();

        Ok(())
    }

    /// Delete a certificate from the database
    pub(crate) fn delete_user_cert(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "DELETE FROM user_certificates WHERE id=?1",
            params![id]
        )?;

        Ok(())
    }

    /// Add a new user to the database
    pub(crate) fn add_user(&self, user: &mut User) -> Result<(), ApiError> {
        self.connection.execute(
            "INSERT INTO users (name, email, password_hash, oidc_id, role) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user.name, user.email, user.password_hash.clone().map(|hash| hash.to_string()), user.oidc_id, user.role as u8],
        )?;

        user.id = self.connection.last_insert_rowid();
        Ok(())
    }

    /// Delete a user from the database
    pub(crate) fn delete_user(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "DELETE FROM users WHERE id=?1",
            params![id]
        )?;

        Ok(())
    }

    /// Update a user in the database
    pub(crate) fn update_user(&self, user: &User) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            "UPDATE users SET name = ?1, email =?2 WHERE id=?3",
            params![user.name, user.email, user.id]
        )?;

        Ok(())
    }

    /// Return a user entry by id from the database
    pub(crate) fn get_user(&self, id: i64) -> Result<User, rusqlite::Error> {
        self.connection.query_row(
            "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE id=?1",
            params![id],
            |row| {
                let hash: Option<String> = row.get(3)?;
                let hash_string = match hash {
                    Some(hash) => PasswordHashString::from_str(hash.as_str()).ok(),
                    None => None
                };
                let role_number: u8 = row.get(5)?;
                Ok(User {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    password_hash: hash_string,
                    oidc_id: row.get(4)?,
                    role: UserRole::try_from(role_number).unwrap(),
                })
            }
        )
    }

    /// Return a user entry by email from the database
    pub(crate) fn get_user_by_email(&self, email: &str) -> Result<User, ApiError> {
        self.connection.query_row(
            "SELECT id, name, email, password_hash, oidc_id, role FROM users WHERE email=?1",
            params![email],
            |row| {
                let hash: String = row.get(3)?;
                let role_number: u8 = row.get(5)?;
                Ok(User {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    password_hash: PasswordHashString::from_str(hash.as_str()).ok(),
                    oidc_id: row.get(4)?,
                    role: UserRole::try_from(role_number).map_err(|_| rusqlite::Error::QueryReturnedNoRows)?,
                })
            }
        ).map_err(|_| ApiError::Database(rusqlite::Error::QueryReturnedNoRows))
    }

    /// Return all users from the database
    pub(crate) fn get_all_user(&self) -> Result<Vec<User>, rusqlite::Error>{
        let mut stmt = self.connection.prepare("SELECT id, name, email, role FROM users")?;
        let query = stmt.query([])?;
        query.map(|row| {
                Ok(User {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    password_hash: None,
                    oidc_id: None,
                    role: row.get(3)?
                })
            })
            .collect()
    }

    /// Set a new password for a user
    /// The password needs to be hashed already
    pub(crate) fn set_user_password(&self, id: i64, password_hash: &String) -> Result<(), ApiError> {
        self.connection.execute(
            "UPDATE users SET password_hash = ?1 WHERE id=?2",
            params![password_hash, id]
        )?;

        Ok(())
    }

    /// Register a user with an OIDC ID:
    /// If the user does not exist, a new user is created.
    /// If the user already exists and has matching OIDC ID, nothing is done.
    /// If the user already exists but has no OIDC ID, the OIDC ID is added.
    /// If the user already exists but has a different OIDC ID, an error is returned.
    /// The function adds the user id and role to the User struct
    pub(crate) fn register_oidc_user(&self, user: &mut User) -> Result<(), ApiError> {
        let existing_oidc_user_option: Option<(i64, UserRole)> = self.connection.query_row(
            "SELECT id, role FROM users WHERE oidc_id=?1",
            params![user.oidc_id],
            |row| Ok((row.get(0)?, row.get(1)?))
        ).ok();

        if let Some(existing_oidc_user) = existing_oidc_user_option {
            // User with the correct OIDC_ID exists
            user.id = existing_oidc_user.0;
            user.role = existing_oidc_user.1;
            Ok(())
        } else {
            // User with the correct OIDC_ID does not exist
            let existing_local_user_option = self.connection.query_row(
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
                // Local user account exists
                if existing_local_user_option.1.is_some() {
                    // Local user account has already a different OIDC_ID
                    Err(ApiError::Unauthorized(Some("OIDC Subject ID mismatch".to_string())))
                } else {
                    // Local user account does not have a OIDC_ID
                    self.connection.execute(
                        "UPDATE users SET oidc_id = ?1 WHERE id=?2",
                        params![user.oidc_id, existing_local_user_option.0]
                    )?;
                    user.id = existing_local_user_option.0;
                    user.role = existing_local_user_option.2;
                    Ok(())
                }
            } else {
                // Local user account does not exist
                self.add_user(user)
            }
        }
    }

    /// Check if the database is setup
    /// Returns true if the database contains at least one user
    /// Returns false if the database is empty
    pub(crate) fn is_setup(&self) -> bool {
        self.connection.query_row(
            "SELECT id FROM users",
            [],
            |_| Ok(())
        ).is_ok()
    }
}