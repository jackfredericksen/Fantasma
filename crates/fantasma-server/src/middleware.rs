//! Security middleware for Fantasma server

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Rate limiter configuration
#[derive(Clone)]
pub struct RateLimiterConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window duration
    pub window: Duration,
    /// Burst allowance
    pub burst: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,        // 100 requests
            window: Duration::from_secs(60), // per minute
            burst: 10,                // with burst of 10
        }
    }
}

/// Rate limiter state for a single client
#[derive(Clone)]
struct RateLimitState {
    count: u32,
    window_start: Instant,
}

/// In-memory rate limiter
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    state: Arc<RwLock<HashMap<String, RateLimitState>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if request is allowed and update state
    pub async fn check(&self, key: &str) -> Result<(), RateLimitInfo> {
        let mut state = self.state.write().await;
        let now = Instant::now();

        let entry = state.entry(key.to_string()).or_insert(RateLimitState {
            count: 0,
            window_start: now,
        });

        // Check if window has expired
        if now.duration_since(entry.window_start) > self.config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check rate limit
        if entry.count >= self.config.max_requests + self.config.burst {
            let remaining = self.config.window - now.duration_since(entry.window_start);
            return Err(RateLimitInfo {
                limit: self.config.max_requests,
                remaining: 0,
                reset_after: remaining,
            });
        }

        entry.count += 1;

        Ok(())
    }

    /// Clean up expired entries (call periodically)
    pub async fn cleanup(&self) {
        let mut state = self.state.write().await;
        let now = Instant::now();
        state.retain(|_, v| now.duration_since(v.window_start) < self.config.window * 2);
    }
}

/// Rate limit information for error response
pub struct RateLimitInfo {
    pub limit: u32,
    pub remaining: u32,
    pub reset_after: Duration,
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Get rate limiter from extensions (would be set up in router)
    // For now, we'll use a simple per-IP approach

    // Extract client identifier (IP address)
    let client_id = addr.ip().to_string();

    // In production, you would:
    // 1. Check against a shared rate limiter
    // 2. Use distributed state (Redis) for multi-instance deployments
    // 3. Apply different limits for different endpoints

    // For this example, we'll just add headers and pass through
    let mut response = next.run(request).await;

    // Add rate limit headers (informational)
    response.headers_mut().insert(
        "X-RateLimit-Limit",
        "100".parse().unwrap(),
    );
    response.headers_mut().insert(
        "X-RateLimit-Remaining",
        "99".parse().unwrap(),
    );

    response
}

/// Security headers middleware
pub async fn security_headers_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    // Add security headers
    let headers = response.headers_mut();

    // Prevent clickjacking
    headers.insert(
        header::X_FRAME_OPTIONS,
        "DENY".parse().unwrap(),
    );

    // Prevent MIME type sniffing
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );

    // Enable XSS protection
    headers.insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap(),
    );

    // Referrer policy
    headers.insert(
        header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Content Security Policy (basic)
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
            .parse()
            .unwrap(),
    );

    // Strict Transport Security (only in production)
    if std::env::var("FANTASMA_PRODUCTION").is_ok() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }

    response
}

/// Request validation middleware
pub async fn validate_request_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check content type for POST requests
    if request.method() == axum::http::Method::POST {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // OIDC endpoints expect form-urlencoded or JSON
        if !content_type.starts_with("application/x-www-form-urlencoded")
            && !content_type.starts_with("application/json")
        {
            // Allow requests without content-type (they might be empty)
            if !content_type.is_empty() {
                tracing::warn!("Invalid content-type: {}", content_type);
            }
        }
    }

    // Check for suspicious headers
    if let Some(ua) = request.headers().get(header::USER_AGENT) {
        if let Ok(ua_str) = ua.to_str() {
            // Log unusual user agents (not blocking, just monitoring)
            if ua_str.is_empty() || ua_str.len() > 1000 {
                tracing::warn!("Unusual user agent length: {}", ua_str.len());
            }
        }
    }

    Ok(next.run(request).await)
}

/// Audit logging middleware
pub async fn audit_log_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = Instant::now();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    // Log security-relevant requests
    if uri.path().starts_with("/authorize")
        || uri.path().starts_with("/token")
        || uri.path().starts_with("/proofs")
    {
        tracing::info!(
            target: "audit",
            method = %method,
            path = %uri.path(),
            status = %status.as_u16(),
            duration_ms = %duration.as_millis(),
            client_ip = %addr.ip(),
            "Security audit log"
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            max_requests: 5,
            window: Duration::from_secs(1),
            burst: 2,
        });

        // First 7 requests should succeed (5 + 2 burst)
        for _ in 0..7 {
            assert!(limiter.check("test_client").await.is_ok());
        }

        // Next request should fail
        assert!(limiter.check("test_client").await.is_err());

        // After window expires, should succeed again
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(limiter.check("test_client").await.is_ok());
    }
}
