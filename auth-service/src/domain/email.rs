#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Email (String);

impl Email {
    pub fn parse(input: String) -> Result<Email, String> {
        if input.contains('@') {
            Ok(Email(input))
        } else {
            Err(format!("{} is an invalid email address :(", input))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    #[test]
    fn test_parse() {
        let email = Email::parse("email".to_string());
        assert!(email.is_err());

        let email = Email::parse("email@".to_string());
        assert!(email.is_ok());
    }
}