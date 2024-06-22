use std::collections::HashSet;

use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn ban_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn check_if_token_is_banned(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ban_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = Secret::new("test_token".to_owned());

        let result = store.ban_token(token.clone()).await;

        assert!(result.is_ok());
        assert!(store.banned_tokens.contains(token.expose_secret()));
    }

    #[tokio::test]
    async fn test_check_if_token_is_banned() {
        let mut store = HashsetBannedTokenStore::default();
        let banned_token = Secret::new("test_token".to_owned());
        let token = Secret::new("this should fail".to_owned());

        store.banned_tokens.insert(banned_token.expose_secret().clone());

        let banned_result = store.check_if_token_is_banned(&banned_token).await.unwrap();
        let allowed_result = store.check_if_token_is_banned(&token).await.unwrap();

        assert!(banned_result);
        assert!(!allowed_result);
    }
}

