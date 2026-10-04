use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;
use crate::jwa::{JwsSigner, JwsVerifier};
use crate::policy::VerificationPolicy;

/**
 * Разобранный JWS Compact Serialization.
 *
 * Исходные сегменты сохраняются неизменными, поскольку именно они участвуют
 * в вычислении JWS Signing Input.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactJws {
    protected: String,
    payload: String,
    signature: String,
}

/**
 * Результат успешно выполненной криптографической проверки JWS.
 */
#[derive(Debug, Clone)]
pub struct VerifiedJws {
    pub header: JoseHeader,
    pub payload: Vec<u8>,
}

impl CompactJws {
    pub fn protected_segment(&self) -> &str {
        &self.protected
    }

    pub fn payload_segment(&self) -> &str {
        &self.payload
    }

    pub fn signature_segment(&self) -> &str {
        &self.signature
    }

    /**
     * Возвращает декодированный Protected Header.
     */
    pub fn protected_header(&self) -> Result<JoseHeader> {
        let bytes = base64url::decode(&self.protected)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /**
     * Возвращает исходный compact token.
     */
    pub fn to_compact(&self) -> String {
        format!("{}.{}.{}", self.protected, self.payload, self.signature)
    }
}

/**
 * Разбирает JWS Compact Serialization.
 */
pub fn parse_compact(input: &str) -> Result<CompactJws> {
    let segments: Vec<&str> = input.split('.').collect();

    if segments.len() != 3 {
        return Err(JoseError::InvalidSegmentCount {
            expected: 3,
            actual: segments.len(),
        });
    }

    Ok(CompactJws {
        protected: segments[0].to_owned(),
        payload: segments[1].to_owned(),
        signature: segments[2].to_owned(),
    })
}

/**
 * Создаёт обычный JWS Compact Serialization.
 */
pub fn sign_compact(
    header: &JoseHeader,
    payload: &[u8],
    signer: &dyn JwsSigner,
) -> Result<String> {
    sign_compact_internal(header, payload, signer, false)
}

/**
 * Создаёт JWS Compact Serialization с detached payload.
 */
pub fn sign_compact_detached(
    header: &JoseHeader,
    payload: &[u8],
    signer: &dyn JwsSigner,
) -> Result<String> {
    sign_compact_internal(header, payload, signer, true)
}

fn sign_compact_internal(
    header: &JoseHeader,
    payload: &[u8],
    signer: &dyn JwsSigner,
    detached: bool,
) -> Result<String> {
    let algorithm = header.algorithm()?;

    if algorithm != signer.algorithm() {
        return Err(JoseError::AlgorithmMismatch);
    }

    // b64 является известным extension библиотеки.
    header.validate_critical(&["b64".to_owned()])?;

    let protected_json = serde_json::to_vec(header)?;
    let protected = base64url::encode(&protected_json);

    let encoded_payload = if header.payload_is_base64url_encoded() {
        base64url::encode(payload).into_bytes()
    } else {
        payload.to_vec()
    };

    if !detached && !header.payload_is_base64url_encoded() {
        let text = std::str::from_utf8(payload).map_err(|_| JoseError::InvalidUnencodedPayload)?;

        if text.contains('.') {
            return Err(JoseError::InvalidUnencodedPayload);
        }
    }

    let signing_input = build_signing_input(&protected, &encoded_payload);
    let signature = signer.sign(&signing_input)?;

    let payload_segment = if detached {
        String::new()
    } else if header.payload_is_base64url_encoded() {
        String::from_utf8(encoded_payload).map_err(|_| JoseError::InvalidJws)?
    } else {
        std::str::from_utf8(payload)
            .map_err(|_| JoseError::InvalidUnencodedPayload)?
            .to_owned()
    };

    Ok(format!(
        "{}.{}.{}",
        protected,
        payload_segment,
        base64url::encode(&signature)
    ))
}

/**
 * Проверяет JWS Compact Serialization.
 *
 * external_payload необходимо передавать для detached JWS. При attached JWS
 * значение должно быть None.
 */
pub fn verify_compact(
    token: &str,
    external_payload: Option<&[u8]>,
    verifier: &dyn JwsVerifier,
    policy: &VerificationPolicy,
) -> Result<VerifiedJws> {
    let compact = parse_compact(token)?;
    let header = compact.protected_header()?;
    let algorithm = header.algorithm()?;

    policy.check_algorithm(algorithm)?;

    if algorithm != verifier.algorithm() {
        return Err(JoseError::AlgorithmMismatch);
    }

    header.validate_critical(&policy.understood_critical())?;

    let encoded_payload;
    let payload;

    if let Some(external_payload) = external_payload {
        if !compact.payload.is_empty() {
            return Err(JoseError::InvalidJws);
        }

        payload = external_payload.to_vec();

        encoded_payload = if header.payload_is_base64url_encoded() {
            base64url::encode(external_payload).into_bytes()
        } else {
            external_payload.to_vec()
        };
    } else if header.payload_is_base64url_encoded() {
        payload = base64url::decode(&compact.payload)?;
        encoded_payload = compact.payload.as_bytes().to_vec();
    } else {
        payload = compact.payload.as_bytes().to_vec();
        encoded_payload = compact.payload.as_bytes().to_vec();
    }

    let signing_input = build_signing_input(&compact.protected, &encoded_payload);
    let signature = base64url::decode(&compact.signature)?;

    verifier.verify(&signing_input, &signature)?;

    Ok(VerifiedJws { header, payload })
}

fn build_signing_input(protected: &str, encoded_payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(protected.len() + 1 + encoded_payload.len());

    output.extend_from_slice(protected.as_bytes());
    output.push(b'.');
    output.extend_from_slice(encoded_payload);

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::HmacKey;

    #[test]
    fn roundtrip_hs256() {
        let mut header = JoseHeader::default();
        header.alg = Some("HS256".to_owned());
        header.typ = Some("JWT".to_owned());

        let key = HmacKey::new("HS256", vec![0x42; 32]).unwrap();
        let token = sign_compact(&header, b"hello", &key).unwrap();

        let policy = VerificationPolicy::new().allow_algorithm("HS256");
        let verified = verify_compact(&token, None, &key, &policy).unwrap();

        assert_eq!(verified.payload, b"hello");
    }

    #[test]
    fn detached_b64_false_roundtrip() {
        let mut header = JoseHeader::default();
        header.alg = Some("HS256".to_owned());
        header.b64 = Some(false);
        header.crit = vec!["b64".to_owned()];

        let key = HmacKey::new("HS256", vec![0x24; 32]).unwrap();
        let payload = b"\x00\x01binary.payload";
        let token = sign_compact_detached(&header, payload, &key).unwrap();

        let policy = VerificationPolicy::new()
            .allow_algorithm("HS256")
            .understand_critical("b64");

        let verified = verify_compact(&token, Some(payload), &key, &policy).unwrap();

        assert_eq!(verified.payload, payload);
    }
}
