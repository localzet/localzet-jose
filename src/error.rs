use thiserror::Error;

/**
 * Ошибка библиотеки JOSE.
 */
#[derive(Debug, Error)]
pub enum JoseError {
    /**
     * Некорректное Base64URL-представление.
     */
    #[error("Некорректное Base64URL-представление")]
    Base64,

    /**
     * Ошибка сериализации или десериализации JSON.
     */
    #[error("Ошибка JSON: {0}")]
    Json(#[from] serde_json::Error),

    /**
     * Некорректное количество сегментов Compact Serialization.
     */
    #[error("Некорректное количество сегментов: ожидалось {expected}, получено {actual}")]
    InvalidSegmentCount { expected: usize, actual: usize },

    /**
     * В защищённом заголовке отсутствует обязательный параметр.
     */
    #[error("Отсутствует обязательный Header Parameter: {0}")]
    MissingHeaderParameter(&'static str),

    /**
     * Значение alg/enc неизвестно текущему криптографическому backend.
     */
    #[error("Алгоритм не поддерживается текущим backend: {0}")]
    UnsupportedAlgorithm(String),

    /**
     * Алгоритм в токене не совпадает с выбранным ключом/провайдером.
     */
    #[error("Алгоритм токена не совпадает с алгоритмом криптографического провайдера")]
    AlgorithmMismatch,

    /**
     * Алгоритм не разрешён политикой вызывающей стороны.
     */
    #[error("Алгоритм не разрешён политикой проверки: {0}")]
    AlgorithmNotAllowed(String),

    /**
     * Ошибка проверки цифровой подписи или MAC.
     */
    #[error("Ошибка проверки подписи")]
    InvalidSignature,

    /**
     * Некорректный или несовместимый криптографический ключ.
     */
    #[error("Некорректный или несовместимый криптографический ключ")]
    InvalidKey,

    /**
     * Ключ недостаточной длины для выбранного алгоритма.
     */
    #[error("Недостаточная длина ключа: требуется минимум {required} байт, получено {actual}")]
    WeakKey { required: usize, actual: usize },

    /**
     * Критический Header Parameter не поддерживается вызывающей стороной.
     */
    #[error("Неизвестный критический Header Parameter: {0}")]
    UnsupportedCriticalHeader(String),

    /**
     * Некорректное значение crit.
     */
    #[error("Некорректный Header Parameter crit")]
    InvalidCriticalHeader,

    /**
     * Некорректное использование b64=false.
     */
    #[error("При b64=false параметр b64 должен присутствовать в crit")]
    MissingB64Critical,

    /**
     * Unencoded Payload не может быть представлен в Compact Serialization.
     */
    #[error("Unencoded Payload содержит символ '.', используйте detached payload или JSON Serialization")]
    InvalidUnencodedPayload,

    /**
     * Некорректная структура JWS.
     */
    #[error("Некорректная структура JWS")]
    InvalidJws,

    /**
     * Некорректная структура JWE.
     */
    #[error("Некорректная структура JWE")]
    InvalidJwe,

    /**
     * Некорректная структура JWT.
     */
    #[error("Некорректная структура JWT")]
    InvalidJwt,

    /**
     * Ошибка криптографической операции.
     */
    #[error("Ошибка криптографической операции")]
    Crypto,

    /**
     * Ошибка аутентификации ciphertext.
     */
    #[error("Ошибка аутентификации зашифрованных данных")]
    AuthenticationFailed,

    /**
     * JWT истёк.
     */
    #[error("Срок действия JWT истёк")]
    Expired,

    /**
     * JWT ещё не должен приниматься.
     */
    #[error("JWT ещё не вступил в силу")]
    NotYetValid,

    /**
     * iat находится недопустимо далеко в будущем.
     */
    #[error("JWT содержит недопустимое значение iat")]
    InvalidIssuedAt,

    /**
     * Issuer не соответствует ожидаемому.
     */
    #[error("Issuer JWT не соответствует ожидаемому")]
    IssuerMismatch,

    /**
     * Audience не соответствует ожидаемой.
     */
    #[error("Audience JWT не соответствует ожидаемой")]
    AudienceMismatch,

    /**
     * Отсутствует обязательный claim.
     */
    #[error("Отсутствует обязательный JWT Claim: {0}")]
    MissingClaim(&'static str),

    /**
     * Некорректное значение JWT Claim.
     */
    #[error("Некорректное значение JWT Claim: {0}")]
    InvalidClaim(&'static str),
}

pub type Result<T> = std::result::Result<T, JoseError>;
