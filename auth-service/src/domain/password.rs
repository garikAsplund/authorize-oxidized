#[derive(Debug, Clone, PartialEq)]
pub struct Password (String);

impl Password {
    pub fn parse(input: String) -> Result<Password, String> {
        if input.len() >= 8 {
            Ok(Password(input))
        } else {
            Err(format!("{} is too short of a password. Passwords must contain at least 8 characters :)", input))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    #[test]
    fn test_parse() {
        let password = Password::parse("assword".to_string());
        assert!(password.is_err());

        let password = Password::parse("password123".to_string());
        assert!(password.is_ok());
    }
}