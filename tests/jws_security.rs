use localzet_jose::{
    header::JoseHeader,
    jwa::HmacKey,
    jws::{sign_compact, verify_compact},
    VerificationPolicy,
};

fn signed() -> (HmacKey, String) {
    let key = HmacKey::new("HS256", vec![0x55; 32]).unwrap();
    let header = JoseHeader {
        alg: Some("HS256".into()),
        ..Default::default()
    };
    let token = sign_compact(&header, b"payload", &key).unwrap();
    (key, token)
}

#[test]
fn requires_explicit_algorithm_and_matching_provider() {
    let (key, token) = signed();
    assert!(verify_compact(&token, None, &key, &VerificationPolicy::new()).is_err());
    let other = HmacKey::new("HS384", vec![0x55; 48]).unwrap();
    let policy = VerificationPolicy::new().allow_algorithm("HS256");
    assert!(verify_compact(&token, None, &other, &policy).is_err());
}

#[test]
fn rejects_wrong_key_and_modified_payload() {
    let (key, token) = signed();
    let policy = VerificationPolicy::new().allow_algorithm("HS256");
    let other = HmacKey::new("HS256", vec![0x66; 32]).unwrap();
    assert!(verify_compact(&token, None, &other, &policy).is_err());
    let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
    parts[1] = "dGFtcGVyZWQ".into();
    assert!(verify_compact(&parts.join("."), None, &key, &policy).is_err());
}

#[test]
fn rejects_weak_keys_and_malformed_compact() {
    assert!(HmacKey::new("HS256", vec![0; 31]).is_err());
    let (key, _) = signed();
    let policy = VerificationPolicy::new().allow_algorithm("HS256");
    for token in ["", "a.b", "a.b.c.d", "!.!.!"] {
        assert!(verify_compact(token, None, &key, &policy).is_err());
    }
}
