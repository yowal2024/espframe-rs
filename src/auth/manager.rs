use super::AuthClientError;

pub struct AuthManagerBoundary;

impl AuthManagerBoundary {
    #[allow(non_snake_case)]
    pub fn FailureJson(error: &AuthClientError) -> String {
        let (code, msg) = match error {
            AuthClientError::TokenUnavailable => (-401, "token unavailable"),
            _ => (-500, "transport failure"),
        };
        serde_json::json!({"code": code, "msg": msg, "ok": false}).to_string()
    }
}
