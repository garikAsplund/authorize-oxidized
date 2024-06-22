use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use secrecy::{ExposeSecret, Secret};

#[tokio::test]
async fn should_return_200_if_correct_code() {
    // Make sure to assert the auth cookie gets set
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let (login_attempt_id, two_fa_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id.as_ref().expose_secret(),
        "2FACode": two_fa_code.as_ref().expose_secret(),
    });

    let response = app.post_verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let inputs = [
        serde_json::json!({
            "email": "random_email",
            "loginAttemptId": "a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8",
            "2FACode": "123456",
        }),
        serde_json::json!({
            "email": "random@email",
            "loginAttemptId": "a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8",
            "2FACode": "false",
        }),
        serde_json::json!({
            "email": "random@email",
            "loginAttemptId": "yea",
            "2FACode": "123456",
        }),
        serde_json::json!({
            "email": "eamail@aim.com",
            "loginAttemptId": "passworrdord123",
            "2FACode": "true",
        }),
        serde_json::json!({
            "email": "yes",
            "loginAttemptId": "yes",
            "2FACode": "true",
        }),
    ];

    for input in inputs.iter() {
        let response = app.post_verify_2fa(&input).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            input
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": "a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8",
        "2FACode": "123456",
    });

    let response = app.post_verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login request. This should fail.
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let first_response = app.post_login(&login_body).await;

    let (_, first_2FA_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let second_response = app.post_login(&login_body).await;

    assert_eq!(second_response.status().as_u16(), 206);

    let login_attempt_id = second_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse")
        .login_attempt_id;

    let body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id,
        "2FACode": first_2FA_code.as_ref().expose_secret(),
    });

    let response = app.post_verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let first_response = app.post_login(&login_body).await;

    let (first_login_attempt_id, first_two_fa_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": first_login_attempt_id.as_ref().expose_secret(),
        "2FACode": first_two_fa_code.as_ref().expose_secret(),
    });

    let response = app.post_verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 200);

    app.post_logout().await;

    let response = app.post_verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    // let body = serde_json::json!({
    //     "email": "random_email",
    //     "login_attempt_id": "passworrdord123",
    //     "two_fa_code": true,
    // });

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "random_email",
            "password": "password123",
            "requires2FA": 12
        }),
        serde_json::json!({
            "email": 12,
            "password": "password123",
        }),
        serde_json::json!({
            "email": 32,
            "password": "password123",
            "requires2FA": "true",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}
