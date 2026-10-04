use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

/**
 * Значение NumericDate.
 *
 * RFC 7519 определяет NumericDate как число секунд от Unix Epoch
 * и допускает нецелые значения. Поэтому число сохраняется как JSON Number,
 * а преобразование в f64 выполняется только при валидации времени.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NumericDate(pub Number);

impl NumericDate {
    /**
     * Создаёт NumericDate из целого количества секунд.
     */
    pub fn from_i64(seconds: i64) -> Self {
        Self(Number::from(seconds))
    }

    /**
     * Возвращает значение времени как f64.
     */
    pub fn as_f64(&self) -> Option<f64> {
        self.0.as_f64()
    }
}

/**
 * Значение зарегистрированного утверждения aud.
 *
 * RFC 7519 допускает как одиночную строку, так и массив строк.
 */
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    /**
     * Проверяет наличие указанной аудитории.
     */
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(value) => value == expected,
            Self::Multiple(values) => values.iter().any(|value| value == expected),
        }
    }
}

/**
 * JWT Claims Set.
 *
 * Семь claims из RFC 7519 представлены типизированными полями.
 * Остальные зарегистрированные IANA claims и пользовательские claims
 * сохраняются без потерь в additional.
 *
 * Это намеренное решение: IANA JWT Claims Registry расширяемый, а тип
 * конкретного claim определяется спецификацией, которая его зарегистрировала.
 */
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<NumericDate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<NumericDate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<NumericDate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /**
     * Все остальные зарегистрированные и частные claims.
     */
    #[serde(flatten)]
    pub additional: Map<String, Value>,
}

impl JwtClaims {
    /**
     * Возвращает произвольный claim по имени.
     *
     * Для семи claims RFC 7519 следует использовать типизированные поля.
     */
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.additional.get(name)
    }

    /**
     * Добавляет произвольный claim.
     */
    pub fn insert(&mut self, name: impl Into<String>, value: Value) -> Option<Value> {
        self.additional.insert(name.into(), value)
    }

    /**
     * Удаляет произвольный claim.
     */
    pub fn remove(&mut self, name: &str) -> Option<Value> {
        self.additional.remove(name)
    }
}
