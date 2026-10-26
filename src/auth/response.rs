use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthResponse {
    pub code: i64,
    #[serde(default)]
    pub msg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthEnvelope {
    pub code: i64,
    pub msg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AuthEnvelopeError {
    #[error("malformed response JSON: {0}")]
    MalformedJson(String),
    #[error("response is missing integer code")]
    MissingCode,
    #[error("server time is not an integer")]
    NonIntegerServerTime,
}

impl AuthEnvelope {
    #[allow(non_snake_case)]
    pub fn Build(code: i64, msg: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code,
            msg: msg.into(),
            data,
        }
    }

    #[allow(non_snake_case)]
    pub fn Parse(input: &str) -> Result<Self, AuthEnvelopeError> {
        let value: Value = serde_json::from_str(input)
            .map_err(|error| AuthEnvelopeError::MalformedJson(error.to_string()))?;
        let code = value
            .get("code")
            .and_then(Value::as_i64)
            .ok_or(AuthEnvelopeError::MissingCode)?;
        Ok(Self {
            code,
            msg: value
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            data: value.get("data").filter(|value| !value.is_null()).cloned(),
        })
    }
}

impl From<AuthEnvelope> for AuthResponse {
    fn from(value: AuthEnvelope) -> Self {
        Self {
            code: value.code,
            msg: value.msg,
            data: value.data,
        }
    }
}

impl AuthResponse {
    #[allow(non_snake_case)]
    pub fn ServerTime(&self) -> Result<Option<i64>, AuthEnvelopeError> {
        match self.data.as_ref().and_then(|data| data.get("serverTime")) {
            None => Ok(None),
            Some(Value::Number(value)) => value
                .as_i64()
                .map(Some)
                .ok_or(AuthEnvelopeError::NonIntegerServerTime),
            Some(_) => Err(AuthEnvelopeError::NonIntegerServerTime),
        }
    }
}
