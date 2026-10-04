use localzet_jose::{
    claims::NumericDate,
    header::JoseHeader,
    jwa::HmacKey,
    jwt::{self, ClaimsValidation},
    JwtClaims,
    VerificationPolicy,
};

#[test]
fn signed_jwt_roundtrip() {
    let mut header = JoseHeader::default();
    header.alg = Some("HS256".to_owned());
    header.typ = Some("JWT".to_owned());

    let mut claims = JwtClaims::default();
    claims.iss = Some("localzet".to_owned());
    claims.exp = Some(NumericDate::from_i64(2_000_000_000));

    let key = HmacKey::new("HS256", vec![0x55; 32]).unwrap();
    let token = jwt::sign(&header, &claims, &key).unwrap();

    let verification = VerificationPolicy::new().allow_algorithm("HS256");
    let validation = ClaimsValidation::new()
        .at_time(1_900_000_000.0)
        .issuer("localzet")
        .require_expiration(true);

    let (_, decoded) = jwt::verify(&token, &key, &verification, &validation).unwrap();

    assert_eq!(decoded.iss.as_deref(), Some("localzet"));
}
