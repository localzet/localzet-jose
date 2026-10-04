use localzet_jose::{
    header::JoseHeader,
    jwa::Unsecured,
    jws::{sign_compact, verify_compact},
    VerificationPolicy,
};

#[test]
fn unsecured_jws_requires_explicit_policy() {
    let mut header = JoseHeader::default();
    header.alg = Some("none".to_owned());

    let token = sign_compact(&header, b"payload", &Unsecured).unwrap();

    let safe_policy = VerificationPolicy::new().allow_algorithm("none");
    assert!(verify_compact(&token, None, &Unsecured, &safe_policy).is_err());

    let explicit_policy = VerificationPolicy::new()
        .allow_algorithm("none")
        .allow_unsecured(true);

    let verified = verify_compact(&token, None, &Unsecured, &explicit_policy).unwrap();
    assert_eq!(verified.payload, b"payload");
}
