use localzet_jose::{
    jwa::HmacKey,
    jwt::{self, ClaimsValidation},
    JoseHeader,
    JwtClaims,
    VerificationPolicy,
};

fn main() -> localzet_jose::Result<()> {
    let mut header = JoseHeader::default();
    header.alg = Some("HS256".to_owned());
    header.typ = Some("JWT".to_owned());

    let mut claims = JwtClaims::default();
    claims.sub = Some("1234567890".to_owned());

    let key = HmacKey::new("HS256", vec![0x11; 32])?;
    let token = jwt::sign(&header, &claims, &key)?;

    println!("{token}");

    let verification = VerificationPolicy::new().allow_algorithm("HS256");
    let validation = ClaimsValidation::new();

    let (_, claims) = jwt::verify(&token, &key, &verification, &validation)?;

    println!("{claims:#?}");

    Ok(())
}
