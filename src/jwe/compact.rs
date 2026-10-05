// SPDX-FileCopyrightText: 2026 Ivan Zorin <creator@localzet.com> (Localzet contributions)
// SPDX-License-Identifier: AGPL-3.0
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm,
    Aes256Gcm,
    Nonce,
    Tag,
};
use rand::{rngs::OsRng, RngCore};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::base64url;
use crate::error::{JoseError, Result};
use crate::header::JoseHeader;
use crate::policy::JweDecryptionPolicy;

/**
 * Разобранный JWE Compact Serialization.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactJwe {
    pub protected: String,
    pub encrypted_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

/**
 * Результат успешной расшифровки JWE.
 */
#[derive(Debug, Clone)]
pub struct DecryptedJwe {
    pub header: JoseHeader,
    pub plaintext: Vec<u8>,
}

/**
 * Разбирает JWE Compact Serialization на пять сегментов.
 */
pub fn parse_compact(input: &str) -> Result<CompactJwe> {
    let segments: Vec<&str> = input.split('.').collect();

    if segments.len() != 5 {
        return Err(JoseError::InvalidSegmentCount {
            expected: 5,
            actual: segments.len(),
        });
    }

    Ok(CompactJwe {
        protected: segments[0].to_owned(),
        encrypted_key: segments[1].to_owned(),
        iv: segments[2].to_owned(),
        ciphertext: segments[3].to_owned(),
        tag: segments[4].to_owned(),
    })
}

/**
 * Создаёт JWE Compact Serialization с alg=dir и AES-GCM.
 */
pub fn encrypt_compact_dir(
    header: &JoseHeader,
    plaintext: &[u8],
    symmetric_key: &[u8],
) -> Result<String> {
    if header.algorithm()? != "dir" {
        return Err(JoseError::AlgorithmMismatch);
    }

    let protected = base64url::encode(&serde_json::to_vec(header)?);
    let (iv, ciphertext, tag) =
        encrypt_content(header.encryption_algorithm()?, symmetric_key, protected.as_bytes(), plaintext)?;

    Ok(format!(
        "{}..{}.{}.{}",
        protected,
        base64url::encode(&iv),
        base64url::encode(&ciphertext),
        base64url::encode(&tag)
    ))
}

/**
 * Расшифровывает JWE Compact Serialization с alg=dir.
 */
pub fn decrypt_compact_dir(
    token: &str,
    symmetric_key: &[u8],
    policy: &JweDecryptionPolicy,
) -> Result<DecryptedJwe> {
    let compact = parse_compact(token)?;

    if !compact.encrypted_key.is_empty() {
        return Err(JoseError::InvalidJwe);
    }

    let header = decode_header(&compact.protected)?;

    if header.algorithm()? != "dir" {
        return Err(JoseError::AlgorithmMismatch);
    }

    policy.check(header.algorithm()?, header.encryption_algorithm()?)?;

    let plaintext = decrypt_content(
        header.encryption_algorithm()?,
        symmetric_key,
        compact.protected.as_bytes(),
        &base64url::decode(&compact.iv)?,
        &base64url::decode(&compact.ciphertext)?,
        &base64url::decode(&compact.tag)?,
    )?;

    Ok(DecryptedJwe { header, plaintext })
}

/**
 * Создаёт JWE Compact Serialization с RSA key management и AES-GCM content
 * encryption.
 */
pub fn encrypt_compact_rsa(
    header: &JoseHeader,
    plaintext: &[u8],
    public_key: &RsaPublicKey,
) -> Result<String> {
    let algorithm = header.algorithm()?;
    let enc = header.encryption_algorithm()?;
    let cek_length = cek_length(enc)?;

    let mut cek = vec![0u8; cek_length];
    OsRng.fill_bytes(&mut cek);

    let encrypted_key = rsa_wrap(algorithm, public_key, &cek)?;
    let protected = base64url::encode(&serde_json::to_vec(header)?);
    let (iv, ciphertext, tag) = encrypt_content(enc, &cek, protected.as_bytes(), plaintext)?;

    Ok(format!(
        "{}.{}.{}.{}.{}",
        protected,
        base64url::encode(&encrypted_key),
        base64url::encode(&iv),
        base64url::encode(&ciphertext),
        base64url::encode(&tag)
    ))
}

/**
 * Расшифровывает JWE Compact Serialization с RSA key management.
 */
pub fn decrypt_compact_rsa(
    token: &str,
    private_key: &RsaPrivateKey,
    policy: &JweDecryptionPolicy,
) -> Result<DecryptedJwe> {
    let compact = parse_compact(token)?;
    let header = decode_header(&compact.protected)?;
    let algorithm = header.algorithm()?;
    let enc = header.encryption_algorithm()?;

    policy.check(algorithm, enc)?;

    let encrypted_key = base64url::decode(&compact.encrypted_key)?;
    let cek = rsa_unwrap(algorithm, private_key, &encrypted_key)?;

    if cek.len() != cek_length(enc)? {
        return Err(JoseError::InvalidKey);
    }

    let plaintext = decrypt_content(
        enc,
        &cek,
        compact.protected.as_bytes(),
        &base64url::decode(&compact.iv)?,
        &base64url::decode(&compact.ciphertext)?,
        &base64url::decode(&compact.tag)?,
    )?;

    Ok(DecryptedJwe { header, plaintext })
}

fn decode_header(segment: &str) -> Result<JoseHeader> {
    let bytes = base64url::decode(segment)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn cek_length(enc: &str) -> Result<usize> {
    match enc {
        "A128GCM" => Ok(16),
        "A256GCM" => Ok(32),
        "A192GCM" => Err(JoseError::UnsupportedAlgorithm(enc.to_owned())),
        other => Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
    }
}

fn encrypt_content(
    enc: &str,
    cek: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let mut buffer = plaintext.to_vec();
    let nonce = Nonce::from(iv);

    let tag = match enc {
        "A128GCM" => {
            let cipher = Aes128Gcm::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;
            cipher
                .encrypt_in_place_detached(&nonce, aad, &mut buffer)
                .map_err(|_| JoseError::Crypto)?
                .to_vec()
        }
        "A256GCM" => {
            let cipher = Aes256Gcm::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;
            cipher
                .encrypt_in_place_detached(&nonce, aad, &mut buffer)
                .map_err(|_| JoseError::Crypto)?
                .to_vec()
        }
        other => return Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
    };

    Ok((iv.to_vec(), buffer, tag))
}

fn decrypt_content(
    enc: &str,
    cek: &[u8],
    aad: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    if iv.len() != 12 || tag.len() != 16 {
        return Err(JoseError::InvalidJwe);
    }

    let mut buffer = ciphertext.to_vec();
    let iv: [u8; 12] = iv.try_into().map_err(|_| JoseError::InvalidJwe)?;
    let tag: [u8; 16] = tag.try_into().map_err(|_| JoseError::InvalidJwe)?;
    let nonce = Nonce::from(iv);
    let tag = Tag::from(tag);

    match enc {
        "A128GCM" => {
            let cipher = Aes128Gcm::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;
            cipher
                .decrypt_in_place_detached(&nonce, aad, &mut buffer, &tag)
                .map_err(|_| JoseError::AuthenticationFailed)?;
        }
        "A256GCM" => {
            let cipher = Aes256Gcm::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;
            cipher
                .decrypt_in_place_detached(&nonce, aad, &mut buffer, &tag)
                .map_err(|_| JoseError::AuthenticationFailed)?;
        }
        other => return Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
    }

    Ok(buffer)
}

fn rsa_wrap(algorithm: &str, key: &RsaPublicKey, cek: &[u8]) -> Result<Vec<u8>> {
    let mut rng = OsRng;

    match algorithm {
        // RSA1_5 остаётся известным идентификатором JOSE Registry, но
        // намеренно не включён в baseline backend из-за исторического класса
        // padding-oracle атак на RSAES-PKCS1-v1_5.
        "RSA1_5" => Err(JoseError::UnsupportedAlgorithm(algorithm.to_owned())),
        "RSA-OAEP" => key
            .encrypt(&mut rng, Oaep::new::<Sha1>(), cek)
            .map_err(|_| JoseError::Crypto),
        "RSA-OAEP-256" => key
            .encrypt(&mut rng, Oaep::new::<Sha256>(), cek)
            .map_err(|_| JoseError::Crypto),
        "RSA-OAEP-384" => key
            .encrypt(&mut rng, Oaep::new::<Sha384>(), cek)
            .map_err(|_| JoseError::Crypto),
        "RSA-OAEP-512" => key
            .encrypt(&mut rng, Oaep::new::<Sha512>(), cek)
            .map_err(|_| JoseError::Crypto),
        other => Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
    }
}

fn rsa_unwrap(algorithm: &str, key: &RsaPrivateKey, encrypted_key: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        // См. комментарий в rsa_wrap(): baseline не предоставляет
        // RSA1_5 decrypt API, чтобы случайно не создать padding oracle.
        "RSA1_5" => Err(JoseError::UnsupportedAlgorithm(algorithm.to_owned())),
        "RSA-OAEP" => key
            .decrypt(Oaep::new::<Sha1>(), encrypted_key)
            .map_err(|_| JoseError::Crypto),
        "RSA-OAEP-256" => key
            .decrypt(Oaep::new::<Sha256>(), encrypted_key)
            .map_err(|_| JoseError::Crypto),
        "RSA-OAEP-384" => key
            .decrypt(Oaep::new::<Sha384>(), encrypted_key)
            .map_err(|_| JoseError::Crypto),
        "RSA-OAEP-512" => key
            .decrypt(Oaep::new::<Sha512>(), encrypted_key)
            .map_err(|_| JoseError::Crypto),
        other => Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_a256gcm_roundtrip() {
        let mut header = JoseHeader::default();
        header.alg = Some("dir".to_owned());
        header.enc = Some("A256GCM".to_owned());

        let key = [0x7a; 32];
        let token = encrypt_compact_dir(&header, b"secret", &key).unwrap();
        let policy = JweDecryptionPolicy::new()
            .allow_key_management("dir")
            .allow_content_encryption("A256GCM");

        let decoded = decrypt_compact_dir(&token, &key, &policy).unwrap();

        assert_eq!(decoded.plaintext, b"secret");
    }
    #[test]
    fn rejects_invalid_and_modified_aead_inputs() {
        for (algorithm, size) in [("A128GCM", 16), ("A256GCM", 32)] {
            let key = vec![0x55; size];
            let (iv, ciphertext, tag) = encrypt_content(algorithm, &key, b"header", b"payload").unwrap();
            assert_eq!(decrypt_content(algorithm, &key, b"header", &iv, &ciphertext, &tag).unwrap(), b"payload");
            for (aad, nonce, auth_tag) in [
                (b"other".as_slice(), iv.as_slice(), tag.as_slice()),
                (b"header".as_slice(), &iv[..11], tag.as_slice()),
                (b"header".as_slice(), iv.as_slice(), &tag[..15]),
            ] {
                assert!(decrypt_content(algorithm, &key, aad, nonce, &ciphertext, auth_tag).is_err());
            }
            let mut tampered = ciphertext.clone();
            tampered[0] ^= 1;
            assert!(decrypt_content(algorithm, &key, b"header", &iv, &tampered, &tag).is_err());
            assert!(decrypt_content(algorithm, &vec![0x66; size], b"header", &iv, &ciphertext, &tag).is_err());
        }
    }

}
