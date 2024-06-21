use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use sqlx::PgPool;
use std::error::Error;

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    // TODO: Implement all required methods. Note that you will need to make SQL queries against our PostgreSQL instance inside these methods.
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(&user.password.as_ref())
            .await
            .map_err(UserStoreError::UnexpectedError)?;

        let result = sqlx::query!(
            r#"
            INSERT INTO users (email, password_hash, requires_2fa)
            VALUES ($1, $2, $3)
            "#,
            user.email.as_ref(),
            password_hash,
            user.requires_2fa,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())

        // check if user already exists?
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let result = sqlx::query!(
            r#"
            SELECT email, password_hash, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| UserStoreError::UserNotFound)?;

        Ok(User {
            email: Email::parse(result.email)
                .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
            password: Password::parse(result.password_hash)
                .map_err(|e| UserStoreError::UnexpectedError(eyre!(e)))?,
            requires_2fa: result.requires_2fa,
        })
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let result = self.get_user(email).await;

        match result {
            Ok(user) => {
                let password_hash = user.password.as_ref();
                match verify_password_hash(&password_hash, password.as_ref()).await {
                    Ok(_) => Ok(()),
                    Err(_) => Err(UserStoreError::InvalidCredentials),
                }
            }
            Err(_) => Err(UserStoreError::UserNotFound),
        }
    }
}

// Helper function to verify if a given password matches an expected hash
// TODO: Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking
#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<()> {
    let current_span: tracing::Span = tracing::Span::current();
    let expected_password_hash = expected_password_hash.to_string();
    let password_candidate = password_candidate.to_string();

    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(&expected_password_hash)?;

            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                .map_err(|e| e)
        })
    })
    .await??;

    Ok(result)
}

// Helper function to hash passwords before persisting them in the database.
// TODO: Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking
#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &str) -> Result<String> {
    let current_span: tracing::Span = tracing::Span::current();
    let password = password.to_string();

    let password_hash = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            match Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)
            {
                Ok(password_hash) => Ok(password_hash.to_string()),
                Err(e) => Err(e),
            }
            // let password_hash = Argon2::new(
            //     Algorithm::Argon2id,
            //     Version::V0x13,
            //     Params::new(15000, 2, 1, None)?,
            // )
            // .hash_password(password.as_bytes(), &salt)?
            // .to_string();

            // Ok(password_hash)
            // Err(eyre!("oh no!"))
        })
    })
    .await??;

    Ok(password_hash)
}
