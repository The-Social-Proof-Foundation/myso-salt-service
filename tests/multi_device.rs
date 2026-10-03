use myso_salt_service::security::jwt::JwtValidator;
use myso_salt_service::security::session_token::vault_possession_message;
use myso_salt_service::models::JwtClaims;

#[test]
fn user_identifier_unified_across_audiences() {
    let claims_web = JwtClaims {
        iss: "https://accounts.google.com".into(),
        aud: "web-client-id".into(),
        sub: "111631294628286022835".into(),
        exp: 2000000000,
        iat: 1500000000,
        nonce: None,
        email: None,
        email_verified: None,
        name: None,
        picture: None,
        given_name: None,
        family_name: None,
    };

    let claims_ios = JwtClaims {
        iss: "https://accounts.google.com".into(),
        aud: "ios-client-id".into(),
        sub: "111631294628286022835".into(),
        exp: 2100000000,
        iat: 1600000000,
        nonce: Some("random".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
        given_name: None,
        family_name: None,
    };

    let id_web = JwtValidator::generate_user_identifier(&claims_web);
    let id_ios = JwtValidator::generate_user_identifier(&claims_ios);
    assert_eq!(id_web, id_ios, "Identifier must be the same across devices for the same user");
}

#[test]
fn vault_possession_message_binds_subject_address_hash_and_nonce() {
    let message = vault_possession_message("user-1", "0xABC", "hash", "nonce");
    assert_ne!(message, vault_possession_message("user-2", "0xABC", "hash", "nonce"));
    assert_ne!(message, vault_possession_message("user-1", "0xabd", "hash", "nonce"));
    assert_ne!(message, vault_possession_message("user-1", "0xABC", "other", "nonce"));
    assert_ne!(message, vault_possession_message("user-1", "0xABC", "hash", "other"));
    assert_eq!(message, vault_possession_message("user-1", "0xabc", "hash", "nonce"));
}
