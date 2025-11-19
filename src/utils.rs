use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use serde::Serialize;
use serde_json_fmt::JsonFormat;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn get_current_unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

pub fn build_hmac_signature<T>(
    secret: &str,
    timestamp: u64,
    method: &str,
    req_path: &str,
    body: Option<&T>,
) -> Result<String>
where
    T: ?Sized + Serialize,
{
    let body = match body {
        None => None,
        Some(b) => Some(format_hmac_body(b)?),
    };
    build_hmac_signature_from_str(secret, timestamp, method, req_path, body.as_deref())
}

pub fn build_hmac_signature_from_str(
    secret: &str,
    timestamp: u64,
    method: &str,
    req_path: &str,
    body: Option<&str>,
) -> Result<String> {
    let decoded = URL_SAFE
        .decode(secret)
        .context("Can't decode secret to base64")?;
    let message = match body {
        None => format!("{timestamp}{method}{req_path}"),
        Some(s) => format!("{timestamp}{method}{req_path}{s}"),
    };

    let mut mac = HmacSha256::new_from_slice(&decoded).context("HMAC init error")?;
    mac.update(message.as_bytes());

    let result = mac.finalize();

    Ok(URL_SAFE.encode(&result.into_bytes()[..]))
}

pub fn format_hmac_body<T>(body: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(JsonFormat::new()
        .comma(", ")?
        .colon(": ")?
        .format_to_string(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_build_hmac_signature() {
        let body = HashMap::from([("hash", "0x123")]);
        let signature = build_hmac_signature(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            1000000,
            "test-sign",
            "/orders",
            Some(&body),
        )
        .unwrap();

        assert_eq!(signature, "ZwAdJKvoYRlEKDkNMwd5BuwNNtg93kNaR_oU2HrfVvc=");
    }
}
