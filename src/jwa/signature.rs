// SPDX-FileCopyrightText: 2026 Ivan Zorin <creator@localzet.com> (Localzet contributions)
// SPDX-License-Identifier: AGPL-3.0
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rsa::{
    traits::PublicKeyParts,
    Pkcs1v15Sign,
    Pss,
    RsaPrivateKey,
    RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{Signer as _, Verifier as _};

use crate::error::{JoseError, Result};

/**
 * Провайдер создания JWS Signature/MAC.
 */
pub trait JwsSigner {
    /**
     * Возвращает точный идентификатор alg.
     */
    fn algorithm(&self) -> &'static str;

    /**
     * Создаёт подпись над JWS Signing Input.
     */
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>>;
}

/**
 * Провайдер проверки JWS Signature/MAC.
 */
pub trait JwsVerifier {
    /**
     * Возвращает точный идентификатор alg.
     */
    fn algorithm(&self) -> &'static str;

    /**
     * Проверяет подпись над JWS Signing Input.
     */
    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<()>;
}

/**
 * Симметричный ключ HMAC.
 */
#[derive(Clone)]
pub struct HmacKey {
    algorithm: &'static str,
    key: Vec<u8>,
}

impl HmacKey {
    /**
     * Создаёт ключ для HS256/HS384/HS512.
     *
     * RFC 7518 требует ключ длиной не меньше размера hash output.
     */
    pub fn new(algorithm: &'static str, key: impl Into<Vec<u8>>) -> Result<Self> {
        let key = key.into();

        let required = match algorithm {
            "HS256" => 32,
            "HS384" => 48,
            "HS512" => 64,
            other => return Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
        };

        if key.len() < required {
            return Err(JoseError::WeakKey {
                required,
                actual: key.len(),
            });
        }

        Ok(Self { algorithm, key })
    }
}

impl JwsSigner for HmacKey {
    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            "HS256" => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            "HS384" => {
                let mut mac =
                    Hmac::<Sha384>::new_from_slice(&self.key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            "HS512" => {
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(&self.key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            other => Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
        }
    }
}

impl JwsVerifier for HmacKey {
    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<()> {
        match self.algorithm {
            "HS256" => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(input);
                mac.verify_slice(signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
            "HS384" => {
                let mut mac =
                    Hmac::<Sha384>::new_from_slice(&self.key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(input);
                mac.verify_slice(signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
            "HS512" => {
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(&self.key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(input);
                mac.verify_slice(signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
            other => Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
        }
    }
}

/**
 * RSA signer для RS* & PS*.
 */
#[derive(Clone)]
pub struct RsaSigner {
    algorithm: &'static str,
    key: RsaPrivateKey,
}

impl RsaSigner {
    pub fn new(algorithm: &'static str, key: RsaPrivateKey) -> Result<Self> {
        validate_rsa_algorithm(algorithm)?;

        if key.n().bits() < 2048 {
            return Err(JoseError::InvalidKey);
        }

        Ok(Self { algorithm, key })
    }
}

impl JwsSigner for RsaSigner {
    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut rng = OsRng;

        match self.algorithm {
            "RS256" => self
                .key
                .sign(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(input))
                .map_err(|_| JoseError::Crypto),
            "RS384" => self
                .key
                .sign(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(input))
                .map_err(|_| JoseError::Crypto),
            "RS512" => self
                .key
                .sign(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(input))
                .map_err(|_| JoseError::Crypto),
            "PS256" => self
                .key
                .sign_with_rng(&mut rng, Pss::new::<Sha256>(), &Sha256::digest(input))
                .map_err(|_| JoseError::Crypto),
            "PS384" => self
                .key
                .sign_with_rng(&mut rng, Pss::new::<Sha384>(), &Sha384::digest(input))
                .map_err(|_| JoseError::Crypto),
            "PS512" => self
                .key
                .sign_with_rng(&mut rng, Pss::new::<Sha512>(), &Sha512::digest(input))
                .map_err(|_| JoseError::Crypto),
            other => Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
        }
    }
}

/// RSA verifier for RSASSA-PKCS1-v1_5 and RSASSA-PSS.
#[derive(Clone)]
pub struct RsaVerifier {
    algorithm: &'static str,
    key: RsaPublicKey,
}

impl RsaVerifier {
    pub fn new(algorithm: &'static str, key: RsaPublicKey) -> Result<Self> {
        validate_rsa_algorithm(algorithm)?;

        if key.n().bits() < 2048 {
            return Err(JoseError::InvalidKey);
        }

        Ok(Self { algorithm, key })
    }
}

impl JwsVerifier for RsaVerifier {
    fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<()> {
        let result = match self.algorithm {
            "RS256" => self
                .key
                .verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(input), signature),
            "RS384" => self
                .key
                .verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(input), signature),
            "RS512" => self
                .key
                .verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(input), signature),
            "PS256" => self
                .key
                .verify(Pss::new::<Sha256>(), &Sha256::digest(input), signature),
            "PS384" => self
                .key
                .verify(Pss::new::<Sha384>(), &Sha384::digest(input), signature),
            "PS512" => self
                .key
                .verify(Pss::new::<Sha512>(), &Sha512::digest(input), signature),
            other => return Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
        };

        result.map_err(|_| JoseError::InvalidSignature)
    }
}

fn validate_rsa_algorithm(algorithm: &str) -> Result<()> {
    match algorithm {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => Ok(()),
        other => Err(JoseError::UnsupportedAlgorithm(other.to_owned())),
    }
}

/**
 * ECDSA private key.
 */
#[derive(Clone)]
pub enum EcSigningKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    Secp256k1(k256::ecdsa::SigningKey),
}

/**
 * ECDSA public key.
 */
#[derive(Clone)]
pub enum EcVerifyingKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
    Secp256k1(k256::ecdsa::VerifyingKey),
}

/**
 * JWS ECDSA signer.
 *
 * RustCrypto Signature использует fixed-size R || S representation,
 * соответствующее wire-format JOSE, а не ASN.1 DER.
 */
#[derive(Clone)]
pub struct EcdsaSigner {
    key: EcSigningKey,
}

impl EcdsaSigner {
    pub fn new(key: EcSigningKey) -> Self {
        Self { key }
    }
}

impl JwsSigner for EcdsaSigner {
    fn algorithm(&self) -> &'static str {
        match self.key {
            EcSigningKey::P256(_) => "ES256",
            EcSigningKey::P384(_) => "ES384",
            EcSigningKey::P521(_) => "ES512",
            EcSigningKey::Secp256k1(_) => "ES256K",
        }
    }

    fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            EcSigningKey::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input);
                Ok(signature.to_vec())
            }
            EcSigningKey::P384(key) => {
                let signature: p384::ecdsa::Signature = key.sign(input);
                Ok(signature.to_vec())
            }
            EcSigningKey::P521(key) => {
                let signature: p521::ecdsa::Signature = key.sign(input);
                Ok(signature.to_vec())
            }
            EcSigningKey::Secp256k1(key) => {
                let signature: k256::ecdsa::Signature = key.sign(input);
                Ok(signature.to_vec())
            }
        }
    }
}

/**
 * JWS ECDSA verifier.
 */
#[derive(Clone)]
pub struct EcdsaVerifier {
    key: EcVerifyingKey,
}

impl EcdsaVerifier {
    pub fn new(key: EcVerifyingKey) -> Self {
        Self { key }
    }
}

impl JwsVerifier for EcdsaVerifier {
    fn algorithm(&self) -> &'static str {
        match self.key {
            EcVerifyingKey::P256(_) => "ES256",
            EcVerifyingKey::P384(_) => "ES384",
            EcVerifyingKey::P521(_) => "ES512",
            EcVerifyingKey::Secp256k1(_) => "ES256K",
        }
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<()> {
        match &self.key {
            EcVerifyingKey::P256(key) => {
                let signature =
                    p256::ecdsa::Signature::try_from(signature).map_err(|_| JoseError::InvalidSignature)?;
                key.verify(input, &signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
            EcVerifyingKey::P384(key) => {
                let signature =
                    p384::ecdsa::Signature::try_from(signature).map_err(|_| JoseError::InvalidSignature)?;
                key.verify(input, &signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
            EcVerifyingKey::P521(key) => {
                let signature =
                    p521::ecdsa::Signature::try_from(signature).map_err(|_| JoseError::InvalidSignature)?;
                key.verify(input, &signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
            EcVerifyingKey::Secp256k1(key) => {
                let signature =
                    k256::ecdsa::Signature::try_from(signature).map_err(|_| JoseError::InvalidSignature)?;
                key.verify(input, &signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
        }
    }
}

/**
 * Ed25519 signer.
 *
 * RFC 9864 использует полностью определённый идентификатор "Ed25519".
 */
#[derive(Clone)]
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    pub fn new(key: ed25519_dalek::SigningKey) -> Self {
        Self { key }
    }
}

impl JwsSigner for Ed25519Signer {
    fn algorithm(&self) -> &'static str {
        "Ed25519"
    }

    fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        let signature: ed25519_dalek::Signature = self.key.sign(input);
        Ok(signature.to_bytes().to_vec())
    }
}

/**
 * Ed25519 verifier.
 */
#[derive(Clone)]
pub struct Ed25519Verifier {
    key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Verifier {
    pub fn new(key: ed25519_dalek::VerifyingKey) -> Self {
        Self { key }
    }
}

impl JwsVerifier for Ed25519Verifier {
    fn algorithm(&self) -> &'static str {
        "Ed25519"
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> Result<()> {
        let signature =
            ed25519_dalek::Signature::try_from(signature).map_err(|_| JoseError::InvalidSignature)?;

        self.key
            .verify(input, &signature)
            .map_err(|_| JoseError::InvalidSignature)
    }
}

/**
 * Провайдер unsecured JWS (alg=none).
 *
 * Этот алгоритм является частью JOSE registry, но не предоставляет никакой
 * криптографической защиты. Его использование требует явного разрешения
 * VerificationPolicy::allow_unsecured(true) и allow_algorithm("none").
 */
#[derive(Debug, Clone, Copy, Default)]
pub struct Unsecured;

impl JwsSigner for Unsecured {
    fn algorithm(&self) -> &'static str {
        "none"
    }

    fn sign(&self, _input: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl JwsVerifier for Unsecured {
    fn algorithm(&self) -> &'static str {
        "none"
    }

    fn verify(&self, _input: &[u8], signature: &[u8]) -> Result<()> {
        if signature.is_empty() {
            Ok(())
        } else {
            Err(JoseError::InvalidSignature)
        }
    }
}
