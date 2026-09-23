use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use thiserror::Error;

const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
const OUTPUT_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password must contain between 12 and 1024 characters")]
    InvalidPassword,
    #[error("password hashing failed")]
    HashingFailed,
}

#[derive(Clone)]
pub struct PasswordService {
    params: Params,
}

impl PasswordService {
    pub fn new() -> Self {
        Self {
            params: Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(OUTPUT_BYTES))
                .expect("fixed Argon2id parameters are valid"),
        }
    }

    fn argon2(&self) -> Argon2<'_> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }

    pub fn validate(password: &str) -> Result<(), PasswordError> {
        let length = password.chars().count();
        if !(12..=1024).contains(&length) {
            return Err(PasswordError::InvalidPassword);
        }
        Ok(())
    }

    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        Self::validate(password)?;
        self.hash_unchecked(password)
    }

    fn hash_unchecked(&self, password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| PasswordError::HashingFailed)
    }

    pub fn verify(&self, password: &str, encoded_hash: &str) -> bool {
        let Ok(hash) = PasswordHash::new(encoded_hash) else {
            return false;
        };
        self.argon2()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    }

    pub fn needs_rehash(&self, encoded_hash: &str) -> bool {
        let Ok(hash) = PasswordHash::new(encoded_hash) else {
            return true;
        };
        hash.algorithm.as_str() != "argon2id"
            || hash.version != Some(Version::V0x13.into())
            || hash.params.get_decimal("m") != Some(MEMORY_KIB)
            || hash.params.get_decimal("t") != Some(ITERATIONS)
            || hash.params.get_decimal("p") != Some(PARALLELISM)
    }

    pub(crate) fn dummy_hash(&self) -> Result<String, PasswordError> {
        self.hash_unchecked("invalid-dummy-password-value")
    }
}

impl Default for PasswordService {
    fn default() -> Self {
        Self::new()
    }
}
