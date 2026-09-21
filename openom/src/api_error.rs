//! Shared HTTP error contract for every managed API route.
//!
//! All errors render as RFC 9457 `application/problem+json` with a stable code from the generated
//! [`crate::error_codes`] registry. Authentication extractors and account handlers use the same responder as
//! tree/blob/keyring routes, so callers never need route-specific error parsers.

use axum::http::header::{CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Handler error rendered through the shared RFC 9457 response contract.
pub enum ApiError {
    Forbidden,
    NotFound,
    Conflict,
    QuotaExceeded,
    /// Append rate exceeded (abuse gate), carrying a `Retry-After` hint in seconds.
    TooManyRequests(u64),
    /// The requested log tail is no longer retained; the client must bootstrap from a snapshot.
    Gone(String),
    BadRequest(String),
    /// A response with an explicit status, generated error code, safe detail, and optional typed arguments.
    Coded {
        status: StatusCode,
        code: &'static str,
        detail: String,
        args: serde_json::Value,
    },
    /// An internal cause that is logged but never sent to the caller.
    Internal(String),
}

impl ApiError {
    /// An RFC 9457 response with no interpolation arguments.
    #[must_use]
    pub fn coded(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Self::coded_with_args(status, code, detail, serde_json::Value::Null)
    }

    /// An RFC 9457 response with typed interpolation arguments from the error-code registry.
    #[must_use]
    pub fn coded_with_args(
        status: StatusCode,
        code: &'static str,
        detail: impl Into<String>,
        args: serde_json::Value,
    ) -> Self {
        Self::Coded {
            status,
            code,
            detail: detail.into(),
            args,
        }
    }

    /// A `409 Conflict` with a typed code.
    #[must_use]
    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::coded(StatusCode::CONFLICT, code, detail)
    }

    /// A `403 Forbidden` with a typed code.
    #[must_use]
    pub fn forbidden(code: &'static str, detail: impl Into<String>) -> Self {
        Self::coded(StatusCode::FORBIDDEN, code, detail)
    }

    /// A `410 Gone` for a GC-reclaimed blob.
    #[must_use]
    pub fn reaped(detail: impl Into<String>) -> Self {
        Self::coded(StatusCode::GONE, crate::error_codes::BELOW_GC_FLOOR, detail)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use crate::error_codes as ec;

        let null = serde_json::Value::Null;
        let (status, code, detail, retry_after, args): (
            StatusCode,
            &'static str,
            String,
            Option<u64>,
            serde_json::Value,
        ) = match self {
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ec::ACCESS_DENIED,
                "forbidden".into(),
                None,
                null,
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ec::NOT_FOUND,
                "not found".into(),
                None,
                null,
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                ec::VERSION_CONFLICT,
                "version conflict — pull the current snapshot and retry".into(),
                None,
                null,
            ),
            Self::QuotaExceeded => (
                StatusCode::FORBIDDEN,
                ec::QUOTA_EXCEEDED,
                "account resource limit reached".into(),
                None,
                null,
            ),
            Self::TooManyRequests(seconds) => (
                StatusCode::TOO_MANY_REQUESTS,
                ec::RATE_LIMITED,
                "append rate exceeded — retry after the indicated delay".into(),
                Some(seconds),
                null,
            ),
            Self::Gone(message) => (StatusCode::GONE, ec::BELOW_GC_FLOOR, message, None, null),
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                ec::INVALID_REQUEST,
                message,
                None,
                null,
            ),
            Self::Coded {
                status,
                code,
                detail,
                args,
            } => (status, code, detail, None, args),
            Self::Internal(message) => {
                tracing::error!(error = %message, "API handler internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ec::UNAVAILABLE,
                    "internal error".into(),
                    None,
                    null,
                )
            }
        };

        let mut body = serde_json::json!({
            "type": format!("/errors/{code}"),
            "title": ec::title_for(code),
            "status": status.as_u16(),
            "code": code,
            "detail": detail,
        });
        if !args.is_null() {
            body["args"] = args;
        }
        let mut response = (status, axum::Json(body)).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if let Some(seconds) = retry_after {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(RETRY_AFTER, value);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use serde_json::Value;

    use super::ApiError;
    use crate::error_codes as ec;

    #[tokio::test]
    async fn coded_error_uses_problem_details_with_typed_args() {
        let response = ApiError::coded_with_args(
            StatusCode::UNAUTHORIZED,
            ec::STALE_TIMESTAMP,
            "registration timestamp is outside the accepted window",
            serde_json::json!({ "server_time": 42 }),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json")
        );
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("problem body must be readable"),
        )
        .expect("problem body must be JSON");
        assert_eq!(body["code"], ec::STALE_TIMESTAMP);
        assert_eq!(body["status"], StatusCode::UNAUTHORIZED.as_u16());
        assert_eq!(body["args"]["server_time"], 42);
        assert!(ec::ERROR_CODES.iter().any(|meta| meta.code == body["code"]));
    }

    #[tokio::test]
    async fn internal_error_hides_its_cause() {
        let response =
            ApiError::Internal("database password leaked into cause".into()).into_response();
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("problem body must be readable"),
        )
        .expect("problem body must be JSON");

        assert_eq!(body["code"], ec::UNAVAILABLE);
        assert_eq!(body["detail"], "internal error");
        assert!(!body.to_string().contains("database password"));
    }
}
