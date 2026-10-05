use std::collections::BTreeSet;

use crate::error::{JoseError, Result};

/**
 * Политика криптографической проверки JWS/JWT.
 *
 * Алгоритм из недоверенного токена никогда не должен самостоятельно выбирать
 * криптографическую операцию. Вызывающая сторона обязана заранее определить
 * допустимый набор алгоритмов.
 */
#[derive(Debug, Clone, Default)]
pub struct VerificationPolicy {
    allowed_algorithms: BTreeSet<String>,
    understood_critical_headers: BTreeSet<String>,
    allow_unsecured: bool,
}

impl VerificationPolicy {
    /**
     * Создаёт пустую безопасную политику.
     *
     * Пока алгоритм явно не разрешён, проверка будет отклонена.
     */
    pub fn new() -> Self {
        Self::default()
    }

    /**
     * Разрешает указанный алгоритм подписи/MAC.
     */
    pub fn allow_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.allowed_algorithms.insert(algorithm.into());
        self
    }

    /**
     * Указывает Critical Header Parameter, семантику которого понимает caller.
     */
    pub fn understand_critical(mut self, parameter: impl Into<String>) -> Self {
        self.understood_critical_headers.insert(parameter.into());
        self
    }

    /**
     * Явно разрешает JWS alg=none.
     *
     * По умолчанию unsecured JWS запрещён.
     */
    pub fn allow_unsecured(mut self, value: bool) -> Self {
        self.allow_unsecured = value;
        self
    }

    pub(crate) fn check_algorithm(&self, algorithm: &str) -> Result<()> {
        if algorithm == "none" && !self.allow_unsecured {
            return Err(JoseError::AlgorithmNotAllowed(algorithm.to_owned()));
        }

        if !self.allowed_algorithms.contains(algorithm) {
            return Err(JoseError::AlgorithmNotAllowed(algorithm.to_owned()));
        }

        Ok(())
    }

    pub(crate) fn understood_critical(&self) -> Vec<String> {
        self.understood_critical_headers.iter().cloned().collect()
    }
}

/**
 * Политика расшифровки JWE.
 *
 * Параметры alg и enc находятся внутри недоверенного Protected Header,
 * поэтому принимающая сторона должна заранее зафиксировать допустимые
 * алгоритмы управления ключами и шифрования содержимого.
 */
#[derive(Debug, Clone, Default)]
pub struct JweDecryptionPolicy {
    allowed_key_management_algorithms: BTreeSet<String>,
    allowed_content_encryption_algorithms: BTreeSet<String>,
}

impl JweDecryptionPolicy {
    /**
     * Создаёт пустую безопасную политику.
     */
    pub fn new() -> Self {
        Self::default()
    }

    /**
     * Разрешает алгоритм управления ключами JWE (alg).
     */
    pub fn allow_key_management(mut self, algorithm: impl Into<String>) -> Self {
        self.allowed_key_management_algorithms
            .insert(algorithm.into());
        self
    }

    /**
     * Разрешает алгоритм шифрования содержимого JWE (enc).
     */
    pub fn allow_content_encryption(mut self, algorithm: impl Into<String>) -> Self {
        self.allowed_content_encryption_algorithms
            .insert(algorithm.into());
        self
    }

    pub(crate) fn check(&self, key_management: &str, content_encryption: &str) -> Result<()> {
        if !self
            .allowed_key_management_algorithms
            .contains(key_management)
        {
            return Err(JoseError::AlgorithmNotAllowed(key_management.to_owned()));
        }

        if !self
            .allowed_content_encryption_algorithms
            .contains(content_encryption)
        {
            return Err(JoseError::AlgorithmNotAllowed(
                content_encryption.to_owned(),
            ));
        }

        Ok(())
    }
}
