use std::collections::HashMap;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default, Debug)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

// TODO: implement TwoFACodeStore for HashmapTwoFACodeStore
#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::UnexpectedError),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        println!("{:?}", self.codes);
        match self.codes.get(email) {
            Some((login_attempt_id, code)) => Ok((login_attempt_id.clone(), code.clone())),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_code() {
        let mut code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse("rando@gmail.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let result = code_store.add_code(email.clone(), login_attempt_id, code).await;
        assert!(result.is_ok());
        assert!(code_store.codes.contains_key(&email));
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse("random@gmail.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let result = code_store.add_code(email.clone(), login_attempt_id, code).await;
        assert!(result.is_ok());
        assert!(code_store.codes.contains_key(&email));

        let result = code_store.remove_code(&email).await;
        assert!(result.is_ok());
        assert!(!code_store.codes.contains_key(&email));
    }

    #[tokio::test]
    async fn test_get_code() {
        let mut code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse("random1@gmail.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let result = code_store.add_code(email.clone(), login_attempt_id.clone(), code.clone()).await;
        assert!(result.is_ok());
        assert!(code_store.codes.contains_key(&email));

        let result = code_store.get_code(&email).await;
        assert!(result.is_ok());
        assert!(code_store.codes.contains_key(&email));
        assert_eq!(result.unwrap(), (login_attempt_id, code));
    }
}
