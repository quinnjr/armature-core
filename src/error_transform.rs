//! Centralized Error Transformation
//!
//! This module provides a comprehensive error transformation system for handling,
//! formatting, and customizing error responses in a centralized manner.
//!
//! # Features
//!
//! - Configurable error response formats (JSON, plain text, HTML)
//! - Error context and metadata attachment
//! - Sensitive data filtering
//! - Custom error transformers
//! - Error logging integration
//! - Problem Details (RFC 7807) support
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```ignore
//! use armature_core::error_transform::{ErrorTransformer, ErrorConfig, ResponseFormat};
//!
//! let transformer = ErrorTransformer::new()
//!     .format(ResponseFormat::Json)
//!     .include_stack_trace(false)
//!     .filter_sensitive_data(true);
//!
//! let response = transformer.transform(&error, &request);
//! ```
//!
//! ## Custom Transformer
//!
//! ```ignore
//! let transformer = ErrorTransformer::new()
//!     .with_transformer(|error, ctx| {
//!         // Custom transformation logic
//!         Some(ErrorResponse::new(error.status_code())
//!             .message("Custom error message"))
//!     });
//! ```

use crate::{Error, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

/// Compiled PII/secret redaction patterns used by [`ErrorTransformer`].
///
/// These regexes are compiled exactly once at first use rather than on every
/// error transformation. Each entry pairs a case-insensitive compiled pattern
/// with its replacement string. Behaviour is identical to compiling the same
/// patterns per-call; only the compilation cost is amortized.
static SENSITIVE_PATTERNS: LazyLock<Vec<(regex::Regex, &'static str)>> = LazyLock::new(|| {
    // Key names in the spirit of `SENSITIVE_HEADER_FRAGMENTS`: false positives
    // cost a `[FILTERED]`, false negatives leak a credential.
    //
    // SUBSTRING_KEYS may appear anywhere in a key (`new_password`,
    // `x_session_id`). DELIMITED_KEYS are short enough to occur inside
    // innocent words (`shipping`, `businessname`), so they match only as a
    // whole key or a `_`/`-`-separated final segment (`user_pin`, `sms-otp`).
    // A bare `code` is the OAuth authorization code in a query/form body; in
    // JSON it is too often an error code, so only qualified `*_code` keys are
    // filtered there.
    const SUBSTRING_KEYS: &str = "password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|\
                                  authorization|session|credential|cvv|cvc|private[_-]?key|\
                                  jwt|signature|cookie|passcode|card[_-]?number|cc[_-]?num|\
                                  account[_-]?number";
    const DELIMITED_KEYS: &str = "pin|otp|totp|ssn|pass|pw|auth|pan|iban";
    const CODE_KEYS: &str = "(?:auth|authorization|oauth|otp|totp|mfa|2fa|sms|verification|\
                             verify|access|reset|recovery|security|confirmation|one[_-]?time|\
                             pin)[_-]?code";
    // Between a key and its `=`/`:`: optional whitespace (`password = x`) and
    // the closing bracket of a Rails/PHP-style key (`user[password]=x`,
    // `user%5Bpassword%5D=x`).
    const SEP: &str = r"(?:\]|%5d)?\s*[=:]";
    // A JSON key may be dotted or bracketed (`"user.password"`).
    const KEY_CHARS: &str = r"[a-z0-9_.\[\]-]";
    // A JSON value: a string (escapes honoured) or a bare number.
    const JSON_VALUE: &str = r#"(?:"(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*)"#;

    let json_substring =
        format!(r#""({KEY_CHARS}*(?:{SUBSTRING_KEYS}){KEY_CHARS}*)"\s*:\s*{JSON_VALUE}"#);
    let json_delimited = format!(
        r#""((?:[a-z0-9]+[_.\[\]-]+)*(?:{DELIMITED_KEYS}|{CODE_KEYS})\]?)"\s*:\s*{JSON_VALUE}"#
    );
    const FORM_SUBSTRING_KEYS: &str = "passwd|passphrase|session|credential|cvv|cvc|jwt|\
                                       signature|cookie|passcode|card[_-]?number|cc[_-]?num|\
                                       account[_-]?number";
    let form_substring =
        format!(r"(?-u:\b)([a-z0-9_-]*(?:{FORM_SUBSTRING_KEYS})[a-z0-9_-]*){SEP}\s*\S+");
    let form_delimited = format!(
        r"(?-u:\b)((?:[a-z0-9]+(?:[_-]|\[|%5b))*(?:{DELIMITED_KEYS}|{CODE_KEYS}|code)){SEP}\s*\S+"
    );

    let patterns: Vec<(String, &str)> = vec![
        // JSON members whose key names a credential: `"password": "x"`.
        // The key-only patterns below need `=`/`:` right after the key, so a
        // quoted JSON key would slip past them.
        (json_substring, r#""$1":"[FILTERED]""#),
        (json_delimited, r#""$1":"[FILTERED]""#),
        // `Authorization: <scheme> <credentials>`, scheme included, before the
        // bare-key patterns: matching only up to the scheme would leave the
        // credential itself behind.
        (
            format!(r"authorization{SEP}\s*(?:(?:bearer|basic|digest|negotiate|token)\s+)?\S+"),
            "authorization=[FILTERED]",
        ),
        // Passwords
        (format!(r"password{SEP}\s*\S+"), "password=[FILTERED]"),
        (format!(r"pwd{SEP}\s*\S+"), "pwd=[FILTERED]"),
        // API keys
        (format!(r"api[_-]?key{SEP}\s*\S+"), "api_key=[FILTERED]"),
        (format!(r"apikey{SEP}\s*\S+"), "apikey=[FILTERED]"),
        // Tokens
        (format!(r"token{SEP}\s*\S+"), "token=[FILTERED]"),
        (r"bearer\s+\S+".into(), "Bearer [FILTERED]"),
        // Basic credentials are base64 `user:pass`; the length floor keeps
        // prose such as "basic auth failed" intact.
        (r"(?-u:\b)basic\s+[a-z0-9+/]{6,}=*".into(), "Basic [FILTERED]"),
        // Secrets
        (format!(r"secret{SEP}\s*\S+"), "secret=[FILTERED]"),
        // Session ids, passwd, card security codes, PINs, OTPs, SSNs and
        // one-time/authorization codes in `key=value` / `key: value` form.
        (form_substring, "$1=[FILTERED]"),
        (form_delimited, "$1=[FILTERED]"),
        // Card numbers: 13-19 digits (every real PAN length, Amex's 15 and
        // the 19-digit ranges included), optionally split by single spaces or
        // dashes in any grouping. The pattern takes the whole run of digit
        // groups, however long, and `redact_card_run` finds the cards inside
        // it: a match capped at 19 digits could end inside a card that other
        // digits precede (`12 34 4111-1111-1111-1111`) and let it through.
        // Cards are Luhn-checked, so order ids and timestamps survive.
        // Digits are ASCII or fullwidth (`card_digit`), the forms a person
        // types a card in; this class and `redact_card_run` agree on them.
        // Groups may be split by up to three spaces, tabs, dashes (ASCII,
        // en, fullwidth), dots, slashes, underscores or non-breaking /
        // ideographic spaces
        // (`4111 - 1111 - ...` included).
        // No `\b` at the start, so a card glued to a letter or `_`
        // (`ref4111...`, `cc_4111...`) is still a run; the one preceding
        // non-digit is consumed and copied back untouched.
        (
            r"(?:^|[^0-9\x{FF10}-\x{FF19}])[0-9\x{FF10}-\x{FF19}]+(?:[ \t\-./_\x{A0}\x{2013}\x{202F}\x{3000}\x{FF0D}]{1,3}[0-9\x{FF10}-\x{FF19}]+)*"
                .into(),
            CARD_FILTERED,
        ),
        // SSN
        // Same digits as the card pattern: ASCII or fullwidth. Bounded by
        // explicit guards (captured and put back) rather than `\b`: a
        // Unicode word boundary forces the slow regex engine on non-ASCII
        // text, which made redacting a 64 KiB non-ASCII body ~150x slower.
        (
            r"(^|[^0-9\x{FF10}-\x{FF19}A-Za-z_])([0-9\x{FF10}-\x{FF19}]{3}[- ]?[0-9\x{FF10}-\x{FF19}]{2}[- ]?[0-9\x{FF10}-\x{FF19}]{4})($|[^0-9\x{FF10}-\x{FF19}A-Za-z_])"
                .into(),
            "${1}[SSN FILTERED]${3}",
        ),
        // The trailing guard consumes the separator a following SSN needs as
        // its leading guard, so one pass catches every other SSN in a run of
        // them; a second pass catches the rest.
        (
            r"(^|[^0-9\x{FF10}-\x{FF19}A-Za-z_])([0-9\x{FF10}-\x{FF19}]{3}[- ]?[0-9\x{FF10}-\x{FF19}]{2}[- ]?[0-9\x{FF10}-\x{FF19}]{4})($|[^0-9\x{FF10}-\x{FF19}A-Za-z_])"
                .into(),
            "${1}[SSN FILTERED]${3}",
        ),
    ];

    patterns
        .into_iter()
        .filter_map(|(pattern, replacement)| {
            let re = regex::Regex::new(&format!("(?i){pattern}"));
            // A typo here would silently drop a redaction rule in release
            // builds; make it loud in tests.
            debug_assert!(re.is_ok(), "bad redaction pattern {pattern}: {re:?}");
            re.ok().map(|re| (re, replacement))
        })
        .collect()
});

/// Replacement for a card number; also marks the one [`SENSITIVE_PATTERNS`]
/// entry whose matches [`redact_sensitive`] Luhn-checks rather than replacing
/// outright.
const CARD_FILTERED: &str = "[CARD FILTERED]";

/// The value of a digit a card number can be written in: ASCII or fullwidth
/// (`４１１１`), as the card pattern matches them.
fn card_digit(c: char) -> Option<u32> {
    match c {
        '0'..='9' => Some(c as u32 - '0' as u32),
        '\u{FF10}'..='\u{FF19}' => Some(c as u32 - 0xFF10),
        _ => None,
    }
}

/// Luhn checksum over the card digits of `digits` (anything else skipped).
fn luhn_valid(digits: &str) -> bool {
    luhn_sum(digits.chars().filter_map(card_digit)).is_multiple_of(10)
}

/// The Luhn sum of a digit sequence (valid when a multiple of 10).
fn luhn_sum(digits: impl DoubleEndedIterator<Item = u32>) -> u32 {
    digits
        .rev()
        .enumerate()
        .map(|(i, d)| match (i % 2 == 1, d * 2) {
            (false, _) => d,
            (true, doubled) if doubled > 9 => doubled - 9,
            (true, doubled) => doubled,
        })
        .sum()
}

/// `run` (digit groups joined by the separators the card pattern allows,
/// as it matches them) with every card number inside replaced by
/// [`CARD_FILTERED`].
///
/// The run is not necessarily one number: dates, phone numbers, quantities
/// and ids sit next to cards (`qty 2 4111 1111 1111 1111`, `2026-10-30 4111
/// ...`), and Luhn over the joined digits then fails. So every window of
/// whole groups holding 13-19 digits is checked, and every group inside any
/// Luhn-valid window is redacted — over-redacting a neighbouring group is the
/// price of never letting part of a card through.
fn redact_card_run(run: &str) -> String {
    // (start byte, end byte, digit count) of each digit group.
    let mut groups: Vec<(usize, usize, usize)> = Vec::new();
    let mut open: Option<(usize, usize)> = None;
    for (i, c) in run.char_indices() {
        match (card_digit(c).is_some(), open) {
            (true, None) => open = Some((i, 1)),
            (true, Some((s, n))) => open = Some((s, n + 1)),
            (false, Some((s, n))) => {
                groups.push((s, i, n));
                open = None;
            }
            (false, None) => {}
        }
    }
    if let Some((s, n)) = open {
        groups.push((s, run.len(), n));
    }

    let mut covered = vec![false; groups.len()];
    for i in 0..groups.len() {
        let mut digits = 0;
        for j in i..groups.len() {
            digits += groups[j].2;
            if digits > 19 {
                break;
            }
            if digits >= 13 && luhn_valid(&run[groups[i].0..groups[j].1]) {
                covered[i..=j].iter_mut().for_each(|c| *c = true);
            }
        }
        // A card glued to its expiry or CVV (`4111111111111111` + `1226`, or
        // + `123`) is one group of 17-23 digits whose whole is not
        // Luhn-valid. The card comes first, so check the group's 13-19 digit
        // prefixes. This over-redacts some long numeric ids (one of up to
        // seven prefixes passes Luhn by chance), which is the right way to be
        // wrong in a log; groups of 16 or fewer digits are judged whole, so
        // ordinary ids and 13-digit millisecond timestamps are left alone.
        let (start, end, count) = groups[i];
        if !covered[i] && (17..=23).contains(&count) {
            let digits: Vec<u32> = run[start..end].chars().filter_map(card_digit).collect();
            covered[i] = (13..=19)
                .filter(|&len| len < digits.len())
                .any(|len| luhn_sum(digits[..len].iter().copied()).is_multiple_of(10));
        }
    }
    if !covered.contains(&true) {
        return run.to_string();
    }

    // Each stretch of covered groups (with the separators between them)
    // becomes one marker; uncovered groups and their separators stay.
    let mut out = String::with_capacity(run.len());
    let mut copied = 0;
    let mut i = 0;
    while i < groups.len() {
        if !covered[i] {
            i += 1;
            continue;
        }
        let mut j = i;
        while j + 1 < groups.len() && covered[j + 1] {
            j += 1;
        }
        out.push_str(&run[copied..groups[i].0]);
        out.push_str(CARD_FILTERED);
        copied = groups[j].1;
        i = j + 1;
    }
    out.push_str(&run[copied..]);
    out
}

/// `key` as lowercase segments joined by single `_`s: a word boundary is any
/// non-alphanumeric character (`.`, `[`, `:`, `/`, ...), a lower/digit to
/// upper step (`newPin` -> `new_pin`), or the end of an acronym
/// (`XMLToken` -> `xml_token`). The segment-only key names (`pin`, `pw`,
/// `ssn`) match only on these boundaries, so a boundary missed here is a
/// credential logged.
fn normalize_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    let mut out = String::with_capacity(key.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            continue;
        }
        if c.is_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            let boundary =
                prev.is_lowercase() || prev.is_ascii_digit() || (prev.is_uppercase() && next_lower);
            if boundary && !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// All of [`SENSITIVE_PATTERNS`] as one set, so [`redact_sensitive`] can tell
/// in a single scan whether any replacement pass would change its input. Only
/// a hit on the original input matters: a pass that changes nothing cannot
/// create a match for a later one.
static SENSITIVE_PRECHECK: LazyLock<Option<regex::RegexSet>> = LazyLock::new(|| {
    let set = regex::RegexSet::new(SENSITIVE_PATTERNS.iter().map(|(re, _)| re.as_str()));
    debug_assert!(set.is_ok(), "bad redaction precheck: {set:?}");
    set.ok()
});

/// Whether a structured field name — a JSON member key or a form field
/// name — names a credential or PII whose value must not be logged.
///
/// The one key test behind structural body redaction (see
/// `LoggingMiddleware`), so JSON and form bodies agree on what is secret.
/// The key is normalized to lowercase `_`-separated segments before
/// matching (see [`normalize_key`]), so dotted, bracketed, slashed and
/// camelCase names (`user.password`, `user[pin]`, `user/pin`, `newPin`,
/// `XMLToken`) are tested on every segment. Broad on purpose:
/// a false positive costs a `[FILTERED]` in a log line, a false negative
/// leaks a credential.
///
/// A bare `code` is *not* matched: in JSON it is usually an error code.
/// Form callers treat it (the OAuth authorization code) separately.
pub(crate) fn is_sensitive_key(key: &str) -> bool {
    static SENSITIVE_KEY: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
        // Matched against the normalized key, so `_` is the only separator.
        let substring = "password|passwd|passphrase|passcode|pwd|secret|token|api_?key|\
                         authorization|session|credential|cvv|cvc|private_?key|jwt|signature|\
                         cookie|code_?verifier|assertion|card_?number|cc_?num|account_?number";
        let segment = "pass|pw|pin|otp|totp|ssn|auth|pan|iban";
        let code = "(?:auth|authorization|oauth|otp|totp|mfa|2_?fa|sms|verification|verify|\
                    access|reset|recovery|security|confirmation|one_?time|pin)_?code";
        // A final `key` segment is key material (`accessKey`, `signingKey`,
        // `master_key`, a bare `key`); only as a whole segment, so `monkey`
        // and `keyboard` stay readable.
        // `key` as a whole segment anywhere (`signing_key_pem`,
        // `key_material`, `hmac_key_hex`), not as part of a word (`monkey`,
        // `keyboard`).
        let pattern = format!("(?:{substring})|(?:^|_)(?:{segment}|{code}|key)(?:_|$)");
        let re = regex::Regex::new(&pattern);
        debug_assert!(re.is_ok(), "bad sensitive-key pattern: {re:?}");
        re.ok()
    });
    let normalized = normalize_key(key);
    // A pattern that failed to compile treats every key as sensitive: fail
    // closed rather than log secrets.
    SENSITIVE_KEY
        .as_ref()
        .is_none_or(|re| re.is_match(&normalized))
}

/// Replace credentials and common PII in `s` with `[FILTERED]` markers, using
/// [`SENSITIVE_PATTERNS`].
///
/// Best-effort: it recognizes `key=value`, `key: value` and JSON
/// `"key": "value"` shapes for password/secret/token/API-key/authorization/
/// session/credential/PIN/OTP/CVV/SSN/one-time-code names, bearer and basic
/// credentials, Luhn-valid 13-19 digit card numbers, and SSN-like digit runs. It is not a guarantee that arbitrary
/// payloads are free of secrets.
///
/// Borrows `s` back when nothing matches, which is the common case: one
/// [`SENSITIVE_PRECHECK`] scan decides that, so a body of many small strings
/// costs one pass per string rather than one per pattern plus a copy.
pub(crate) fn redact_sensitive(s: &str) -> Cow<'_, str> {
    // A set that failed to build says "maybe" to everything: fall through to
    // the full passes rather than skip redaction.
    if SENSITIVE_PRECHECK
        .as_ref()
        .is_some_and(|set| !set.is_match(s))
    {
        return Cow::Borrowed(s);
    }
    let mut result = Cow::Borrowed(s);
    for (regex, replacement) in SENSITIVE_PATTERNS.iter() {
        let replaced = if *replacement == CARD_FILTERED {
            regex.replace_all(&result, |caps: &regex::Captures<'_>| {
                redact_card_run(&caps[0])
            })
        } else {
            regex.replace_all(&result, *replacement)
        };
        // The card pattern matches every digit run and its closure hands
        // most of them back unchanged; `replace_all` still reports those as
        // `Owned`. Only a real change counts, so callers that read `Owned` as
        // "something was redacted" (and digit-bearing text that needs no
        // redaction) keep the borrowed, unchanged input.
        if let Cow::Owned(replaced) = replaced
            && replaced != *result
        {
            result = Cow::Owned(replaced);
        }
    }
    result
}

// ============================================================================
// Error Response Types
// ============================================================================

/// Format for error responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseFormat {
    /// JSON format (default) - Simple JSON with status, message, etc.
    #[default]
    Json,
    /// Plain text format
    PlainText,
    /// HTML format - Styled error page
    Html,
    /// RFC 7807 Problem Details JSON
    ProblemDetails,
    /// JSON:API error format (<https://jsonapi.org/format/#errors>)
    JsonApi,
    /// GraphQL error format (<https://spec.graphql.org>)
    GraphQL,
    /// Google/gRPC-style error format
    Google,
    /// AWS-style error format
    Aws,
    /// Azure-style error format
    Azure,
}

/// A structured error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// HTTP status code
    pub status: u16,
    /// Error code (application-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Human-readable error message
    pub message: String,
    /// Detailed error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Error type/category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    /// Request path that caused the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Timestamp of the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Request ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Additional metadata
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub metadata: HashMap<String, serde_json::Value>,
    /// Validation errors (for 422 responses)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub validation_errors: Vec<ValidationError>,
    /// Stack trace (if enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,
}

impl ErrorResponse {
    /// Create a new error response.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            code: None,
            message: String::new(),
            details: None,
            error_type: None,
            path: None,
            timestamp: Some(httpdate::fmt_http_date(std::time::SystemTime::now())),
            request_id: None,
            metadata: HashMap::new(),
            validation_errors: Vec::new(),
            stack_trace: None,
        }
    }

    /// Set the error message.
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Set the error code.
    pub fn code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    /// Set the details.
    pub fn details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Set the error type.
    pub fn error_type(mut self, error_type: impl Into<String>) -> Self {
        self.error_type = Some(error_type.into());
        self
    }

    /// Set the request path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the request ID.
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.metadata.insert(key.into(), json_value);
        }
        self
    }

    /// Add a validation error.
    pub fn with_validation_error(mut self, error: ValidationError) -> Self {
        self.validation_errors.push(error);
        self
    }

    /// Add multiple validation errors.
    pub fn with_validation_errors(mut self, errors: Vec<ValidationError>) -> Self {
        self.validation_errors.extend(errors);
        self
    }

    /// Set the stack trace.
    pub fn stack_trace(mut self, trace: impl Into<String>) -> Self {
        self.stack_trace = Some(trace.into());
        self
    }

    /// Convert to JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| {
            // Built with `json!` so a quote or backslash in the message cannot
            // break out of its string and forge fields.
            serde_json::json!({ "status": self.status, "message": self.message }).to_string()
        })
    }

    /// Convert to plain text.
    pub fn to_plain_text(&self) -> String {
        let mut text = format!("Error {}: {}", self.status, self.message);
        if let Some(ref details) = self.details {
            text.push_str(&format!("\nDetails: {}", details));
        }
        if !self.validation_errors.is_empty() {
            text.push_str("\nValidation Errors:");
            for err in &self.validation_errors {
                text.push_str(&format!("\n  - {}: {}", err.field, err.message));
            }
        }
        text
    }

    /// Convert to HTML.
    pub fn to_html(&self) -> String {
        let mut html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Error {}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 40px; background: #f5f5f5; }}
        .error {{ background: white; border-radius: 8px; padding: 24px; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #e53935; margin-top: 0; }}
        .status {{ color: #666; font-size: 14px; }}
        .details {{ background: #f5f5f5; padding: 12px; border-radius: 4px; margin-top: 16px; }}
        .validation {{ margin-top: 16px; }}
        .validation li {{ color: #d32f2f; }}
    </style>
</head>
<body>
    <div class="error">
        <p class="status">Error {}</p>
        <h1>{}</h1>"#,
            self.status,
            self.status,
            html_escape(&self.message)
        );

        if let Some(ref details) = self.details {
            html.push_str(&format!(
                r#"<div class="details">{}</div>"#,
                html_escape(details)
            ));
        }

        if !self.validation_errors.is_empty() {
            html.push_str(r#"<div class="validation"><h3>Validation Errors</h3><ul>"#);
            for err in &self.validation_errors {
                html.push_str(&format!(
                    "<li><strong>{}</strong>: {}</li>",
                    html_escape(&err.field),
                    html_escape(&err.message)
                ));
            }
            html.push_str("</ul></div>");
        }

        html.push_str("</div></body></html>");
        html
    }

    /// Convert to Problem Details (RFC 7807).
    pub fn to_problem_details(&self) -> String {
        let problem = ProblemDetails {
            type_uri: self
                .error_type
                .clone()
                .unwrap_or_else(|| "about:blank".to_string()),
            title: self.message.clone(),
            status: self.status,
            detail: self.details.clone(),
            instance: self.path.clone(),
            extensions: self.metadata.clone(),
        };
        serde_json::to_string_pretty(&problem).unwrap_or_else(|_| self.to_json())
    }

    /// Convert to JSON:API error format.
    /// <https://jsonapi.org/format/#errors>
    pub fn to_json_api(&self) -> String {
        let error = JsonApiError {
            id: self.request_id.clone(),
            status: self.status.to_string(),
            code: self.code.clone(),
            title: Some(self.message.clone()),
            detail: self.details.clone(),
            source: if !self.validation_errors.is_empty() {
                Some(JsonApiErrorSource {
                    pointer: self
                        .validation_errors
                        .first()
                        .map(|e| format!("/data/attributes/{}", e.field)),
                    parameter: None,
                    header: None,
                })
            } else {
                None
            },
            meta: if self.metadata.is_empty() {
                None
            } else {
                Some(self.metadata.clone())
            },
        };

        let response = JsonApiErrorResponse {
            errors: std::iter::once(error)
                .chain(self.validation_errors.iter().skip(1).map(|v| JsonApiError {
                    id: None,
                    status: self.status.to_string(),
                    code: self.code.clone(),
                    title: Some(v.message.clone()),
                    detail: v.rule.clone(),
                    source: Some(JsonApiErrorSource {
                        pointer: Some(format!("/data/attributes/{}", v.field)),
                        parameter: None,
                        header: None,
                    }),
                    meta: None,
                }))
                .collect(),
        };

        serde_json::to_string_pretty(&response).unwrap_or_else(|_| self.to_json())
    }

    /// Convert to GraphQL error format.
    /// <https://spec.graphql.org/October2021/#sec-Errors>
    pub fn to_graphql(&self) -> String {
        let errors: Vec<GraphQLError> = if self.validation_errors.is_empty() {
            vec![GraphQLError {
                message: self.message.clone(),
                locations: None,
                path: self
                    .path
                    .as_ref()
                    .map(|p| vec![serde_json::Value::String(p.clone())]),
                extensions: Some(GraphQLErrorExtensions {
                    code: self.code.clone().or(self.error_type.clone()),
                    status: Some(self.status),
                    timestamp: self.timestamp.clone(),
                    details: self.details.clone(),
                }),
            }]
        } else {
            self.validation_errors
                .iter()
                .map(|v| GraphQLError {
                    message: v.message.clone(),
                    locations: None,
                    path: Some(vec![serde_json::Value::String(v.field.clone())]),
                    extensions: Some(GraphQLErrorExtensions {
                        code: v.rule.clone(),
                        status: Some(self.status),
                        timestamp: None,
                        details: None,
                    }),
                })
                .collect()
        };

        let response = GraphQLErrorResponse { data: None, errors };

        serde_json::to_string_pretty(&response).unwrap_or_else(|_| self.to_json())
    }

    /// Convert to Google/gRPC-style error format.
    pub fn to_google(&self) -> String {
        let error = GoogleError {
            error: GoogleErrorBody {
                code: self.status,
                message: self.message.clone(),
                status: self
                    .error_type
                    .clone()
                    .unwrap_or_else(|| google_status_from_http(self.status)),
                details: self
                    .validation_errors
                    .iter()
                    .map(|v| GoogleErrorDetail {
                        type_url: "type.googleapis.com/google.rpc.BadRequest.FieldViolation"
                            .to_string(),
                        field: v.field.clone(),
                        description: v.message.clone(),
                    })
                    .collect(),
            },
        };

        serde_json::to_string_pretty(&error).unwrap_or_else(|_| self.to_json())
    }

    /// Convert to AWS-style error format.
    pub fn to_aws(&self) -> String {
        let error = AwsError {
            __type: self
                .error_type
                .clone()
                .unwrap_or_else(|| format!("{}Exception", aws_error_type(self.status))),
            message: self.message.clone(),
            code: self.code.clone(),
            request_id: self.request_id.clone(),
        };

        serde_json::to_string_pretty(&error).unwrap_or_else(|_| self.to_json())
    }

    /// Convert to Azure-style error format.
    pub fn to_azure(&self) -> String {
        let inner_errors: Vec<AzureInnerError> = self
            .validation_errors
            .iter()
            .map(|v| AzureInnerError {
                code: v
                    .rule
                    .clone()
                    .unwrap_or_else(|| "ValidationError".to_string()),
                message: v.message.clone(),
                target: Some(v.field.clone()),
            })
            .collect();

        let error = AzureError {
            error: AzureErrorBody {
                code: self.code.clone().unwrap_or_else(|| {
                    self.error_type
                        .clone()
                        .unwrap_or_else(|| "Error".to_string())
                }),
                message: self.message.clone(),
                target: self.path.clone(),
                details: if inner_errors.is_empty() {
                    None
                } else {
                    Some(inner_errors)
                },
                innererror: self.details.as_ref().map(|d| AzureInnerErrorInfo {
                    code: self.error_type.clone(),
                    message: Some(d.clone()),
                }),
            },
        };

        serde_json::to_string_pretty(&error).unwrap_or_else(|_| self.to_json())
    }

    /// Convert to HttpResponse.
    pub fn into_http_response(self, format: ResponseFormat) -> HttpResponse {
        let (body, content_type) = match format {
            ResponseFormat::Json => (self.to_json(), "application/json"),
            ResponseFormat::PlainText => (self.to_plain_text(), "text/plain; charset=utf-8"),
            ResponseFormat::Html => (self.to_html(), "text/html; charset=utf-8"),
            ResponseFormat::ProblemDetails => {
                (self.to_problem_details(), "application/problem+json")
            }
            ResponseFormat::JsonApi => (self.to_json_api(), "application/vnd.api+json"),
            ResponseFormat::GraphQL => (self.to_graphql(), "application/json"),
            ResponseFormat::Google => (self.to_google(), "application/json"),
            ResponseFormat::Aws => (self.to_aws(), "application/x-amz-json-1.1"),
            ResponseFormat::Azure => (self.to_azure(), "application/json"),
        };

        HttpResponse::new(self.status)
            .with_header("Content-Type".to_string(), content_type.to_string())
            .with_body(body.into_bytes())
    }
}

impl Default for ErrorResponse {
    fn default() -> Self {
        Self::new(500).message("Internal Server Error")
    }
}

/// A validation error for a specific field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Field name that failed validation
    pub field: String,
    /// Validation error message
    pub message: String,
    /// Validation rule that failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Invalid value (sanitized)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

impl ValidationError {
    /// Create a new validation error.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            rule: None,
            value: None,
        }
    }

    /// Set the rule that failed.
    pub fn rule(mut self, rule: impl Into<String>) -> Self {
        self.rule = Some(rule.into());
        self
    }

    /// Set the invalid value.
    pub fn value(mut self, value: impl Serialize) -> Self {
        self.value = serde_json::to_value(value).ok();
        self
    }
}

/// RFC 7807 Problem Details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// A URI reference that identifies the problem type
    #[serde(rename = "type")]
    pub type_uri: String,
    /// A short, human-readable summary of the problem
    pub title: String,
    /// The HTTP status code
    pub status: u16,
    /// A human-readable explanation specific to this occurrence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// A URI reference that identifies the specific occurrence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Additional properties
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

// ============================================================================
// JSON:API Error Format (https://jsonapi.org/format/#errors)
// ============================================================================

/// JSON:API error response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonApiErrorResponse {
    /// Array of error objects
    pub errors: Vec<JsonApiError>,
}

/// JSON:API error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonApiError {
    /// Unique identifier for this occurrence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// HTTP status code as string
    pub status: String,
    /// Application-specific error code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Short, human-readable summary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Human-readable explanation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Object containing references to source of error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<JsonApiErrorSource>,
    /// Non-standard meta-information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<HashMap<String, serde_json::Value>>,
}

/// JSON:API error source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonApiErrorSource {
    /// JSON Pointer to the value in request document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// String indicating which query parameter caused the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    /// Name of request header that caused the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

// ============================================================================
// GraphQL Error Format (https://spec.graphql.org/October2021/#sec-Errors)
// ============================================================================

/// GraphQL error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLErrorResponse {
    /// Response data (null for errors)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Array of errors
    pub errors: Vec<GraphQLError>,
}

/// GraphQL error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    /// Error message
    pub message: String,
    /// Locations in GraphQL document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<GraphQLErrorLocation>>,
    /// Path to response field which experienced the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<serde_json::Value>>,
    /// Implementation-specific extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<GraphQLErrorExtensions>,
}

/// GraphQL error location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLErrorLocation {
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number (1-indexed)
    pub column: u32,
}

/// GraphQL error extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLErrorExtensions {
    /// Error code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// HTTP status code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

// ============================================================================
// Google/gRPC Error Format
// ============================================================================

/// Google-style error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleError {
    /// Error body
    pub error: GoogleErrorBody,
}

/// Google error body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleErrorBody {
    /// HTTP status code
    pub code: u16,
    /// Error message
    pub message: String,
    /// gRPC status (INVALID_ARGUMENT, NOT_FOUND, etc.)
    pub status: String,
    /// Error details
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub details: Vec<GoogleErrorDetail>,
}

/// Google error detail (field violation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleErrorDetail {
    /// Type URL
    #[serde(rename = "@type")]
    pub type_url: String,
    /// Field name
    pub field: String,
    /// Description
    pub description: String,
}

/// Map HTTP status to gRPC status string.
fn google_status_from_http(status: u16) -> String {
    match status {
        400 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        409 => "ALREADY_EXISTS",
        429 => "RESOURCE_EXHAUSTED",
        499 => "CANCELLED",
        500 => "INTERNAL",
        501 => "UNIMPLEMENTED",
        503 => "UNAVAILABLE",
        504 => "DEADLINE_EXCEEDED",
        _ => "UNKNOWN",
    }
    .to_string()
}

// ============================================================================
// AWS Error Format
// ============================================================================

/// AWS-style error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsError {
    /// Error type (e.g., "ValidationException")
    #[serde(rename = "__type")]
    pub __type: String,
    /// Error message
    pub message: String,
    /// Error code (optional)
    #[serde(rename = "Code", skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Request ID
    #[serde(rename = "RequestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Map HTTP status to AWS error type prefix.
fn aws_error_type(status: u16) -> String {
    match status {
        400 => "Validation",
        401 => "UnauthorizedAccess",
        403 => "AccessDenied",
        404 => "ResourceNotFound",
        409 => "Conflict",
        429 => "Throttling",
        500 => "InternalService",
        503 => "ServiceUnavailable",
        _ => "Service",
    }
    .to_string()
}

// ============================================================================
// Azure Error Format
// ============================================================================

/// Azure-style error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureError {
    /// Error body
    pub error: AzureErrorBody,
}

/// Azure error body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureErrorBody {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Target of the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Array of details about specific errors
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<AzureInnerError>>,
    /// Inner error for additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub innererror: Option<AzureInnerErrorInfo>,
}

/// Azure inner error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureInnerError {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Target
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Azure inner error info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureInnerErrorInfo {
    /// Error code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ============================================================================
// Error Context
// ============================================================================

/// Context information about an error occurrence.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// The original request
    pub request: HttpRequest,
    /// Request ID
    pub request_id: Option<String>,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// Additional context data
    pub data: HashMap<String, serde_json::Value>,
}

impl ErrorContext {
    /// Create error context from a request.
    pub fn from_request(request: HttpRequest) -> Self {
        // Lookup is case-insensitive, so the second spelling was redundant.
        // Echoed into error bodies, so a client-chosen ID is only adopted
        // when it is well-formed.
        let request_id = request
            .headers
            .get("x-request-id")
            .filter(|id| crate::headers::is_valid_request_id(id))
            .map(str::to_owned);

        Self {
            request,
            request_id,
            user_id: None,
            data: HashMap::new(),
        }
    }

    /// Set the user ID.
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Add context data.
    pub fn with_data(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.data.insert(key.into(), json_value);
        }
        self
    }
}

// ============================================================================
// Error Transformer
// ============================================================================

/// Type alias for custom transformer functions.
pub type TransformerFn = Arc<dyn Fn(&Error, &ErrorContext) -> Option<ErrorResponse> + Send + Sync>;

/// Type alias for error filter functions.
pub type FilterFn = Arc<dyn Fn(&Error) -> Error + Send + Sync>;

/// Type alias for error logging functions.
pub type LoggerFn = Arc<dyn Fn(&Error, &ErrorContext, &ErrorResponse) + Send + Sync>;

/// Centralized error transformer.
pub struct ErrorTransformer {
    /// Response format
    format: ResponseFormat,
    /// Whether to include stack traces
    include_stack_trace: bool,
    /// Whether to filter sensitive data
    filter_sensitive: bool,
    /// Custom transformers (checked in order)
    transformers: Vec<TransformerFn>,
    /// Error filters
    filters: Vec<FilterFn>,
    /// Loggers
    loggers: Vec<LoggerFn>,
    /// Whether to include the request path (never the query) in error bodies.
    /// Off by default.
    include_path: bool,
    /// Whether to include timestamp
    include_timestamp: bool,
    /// Custom error codes mapping
    error_codes: HashMap<String, String>,
    /// Default error messages for production
    production_mode: bool,
}

impl ErrorTransformer {
    /// Create a new error transformer with default settings.
    pub fn new() -> Self {
        Self {
            format: ResponseFormat::Json,
            include_stack_trace: false,
            filter_sensitive: true,
            transformers: Vec::new(),
            filters: Vec::new(),
            loggers: Vec::new(),
            include_path: false,
            include_timestamp: true,
            error_codes: HashMap::new(),
            production_mode: true,
        }
    }

    /// Set the response format.
    pub fn format(mut self, format: ResponseFormat) -> Self {
        self.format = format;
        self
    }

    /// Enable or disable stack trace inclusion.
    pub fn include_stack_trace(mut self, include: bool) -> Self {
        self.include_stack_trace = include;
        self
    }

    /// Enable or disable sensitive data filtering.
    pub fn filter_sensitive_data(mut self, filter: bool) -> Self {
        self.filter_sensitive = filter;
        self
    }

    /// Enable or disable path inclusion (off by default).
    ///
    /// When enabled, only the path is echoed — the query string is always
    /// dropped, since it routinely carries tokens, e-mail addresses and other
    /// values that must not be reflected into a response body.
    pub fn include_path(mut self, include: bool) -> Self {
        self.include_path = include;
        self
    }

    /// Enable or disable timestamp inclusion.
    pub fn include_timestamp(mut self, include: bool) -> Self {
        self.include_timestamp = include;
        self
    }

    /// Set production mode (hides internal error details).
    pub fn production_mode(mut self, production: bool) -> Self {
        self.production_mode = production;
        self
    }

    /// Add a custom transformer.
    pub fn with_transformer<F>(mut self, transformer: F) -> Self
    where
        F: Fn(&Error, &ErrorContext) -> Option<ErrorResponse> + Send + Sync + 'static,
    {
        self.transformers.push(Arc::new(transformer));
        self
    }

    /// Add an error filter.
    pub fn with_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&Error) -> Error + Send + Sync + 'static,
    {
        self.filters.push(Arc::new(filter));
        self
    }

    /// Add a logger.
    pub fn with_logger<F>(mut self, logger: F) -> Self
    where
        F: Fn(&Error, &ErrorContext, &ErrorResponse) + Send + Sync + 'static,
    {
        self.loggers.push(Arc::new(logger));
        self
    }

    /// Map an error type to a code.
    pub fn map_error_code(
        mut self,
        error_type: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        self.error_codes.insert(error_type.into(), code.into());
        self
    }

    /// Transform an error into an HTTP response.
    pub fn transform(&self, error: &Error, request: &HttpRequest) -> HttpResponse {
        let context = ErrorContext::from_request(request.clone());
        self.transform_with_context(error, &context)
    }

    /// Transform an error with full context.
    pub fn transform_with_context(&self, error: &Error, context: &ErrorContext) -> HttpResponse {
        // Apply filters
        let filtered_error = self.apply_filters(error);

        // Try custom transformers first
        for transformer in &self.transformers {
            if let Some(response) = transformer(&filtered_error, context) {
                return self.finalize_response(response, &filtered_error, context);
            }
        }

        // Default transformation
        let response = self.default_transform(&filtered_error, context);
        self.finalize_response(response, &filtered_error, context)
    }

    /// Apply error filters.
    fn apply_filters(&self, error: &Error) -> Error {
        let mut current = if self.filter_sensitive {
            self.filter_error_message(error)
        } else {
            self.clone_error(error)
        };

        // Apply user-registered filters in order
        for filter in &self.filters {
            current = filter(&current);
        }

        current
    }

    /// Clone an error (simplified).
    fn clone_error(&self, error: &Error) -> Error {
        map_error_message(error, |msg| msg.to_string())
    }

    /// Filter sensitive information from error messages.
    fn filter_error_message(&self, error: &Error) -> Error {
        map_error_message(error, |msg| self.filter_sensitive_string(msg))
    }

    /// Filter sensitive strings.
    ///
    /// Uses the module-level [`SENSITIVE_PATTERNS`] regexes, which are compiled
    /// once on first use rather than on every call.
    fn filter_sensitive_string(&self, s: &str) -> String {
        redact_sensitive(s).into_owned()
    }

    /// Default error transformation.
    fn default_transform(&self, error: &Error, context: &ErrorContext) -> ErrorResponse {
        let status = error.status_code();
        let error_type = self.get_error_type(error);

        let mut response = ErrorResponse::new(status).error_type(&error_type);

        // Set message
        if self.production_mode && error.is_server_error() {
            response = response.message("An internal server error occurred");
        } else if self.production_mode {
            // Same client-safe text `Error::to_client_response` uses, so a
            // serde error's internals never reach a production client.
            response = response.message(error.client_message());
        } else {
            response = response.message(error.to_string());
        }

        // Add error code if mapped
        if let Some(code) = self.error_codes.get(&error_type) {
            response = response.code(code);
        }

        // Add path
        if self.include_path {
            response = response.path(context.request.path_only());
        }

        // Add request ID
        if let Some(ref request_id) = context.request_id {
            response = response.request_id(request_id);
        }

        // Add timestamp
        if !self.include_timestamp {
            response.timestamp = None;
        }

        response
    }

    /// Get the error type string.
    fn get_error_type(&self, error: &Error) -> String {
        match error {
            Error::BadRequest(_) => "BAD_REQUEST".to_string(),
            Error::Unauthorized(_) => "UNAUTHORIZED".to_string(),
            Error::Forbidden(_) => "FORBIDDEN".to_string(),
            Error::NotFound(_) => "NOT_FOUND".to_string(),
            Error::Validation(_) => "VALIDATION_ERROR".to_string(),
            Error::Internal(_) => "INTERNAL_ERROR".to_string(),
            Error::Conflict(_) => "CONFLICT".to_string(),
            Error::TooManyRequests(_) => "RATE_LIMITED".to_string(),
            Error::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE".to_string(),
            Error::RequestTimeout(_) => "TIMEOUT".to_string(),
            _ => "ERROR".to_string(),
        }
    }

    /// Finalize the response and log.
    fn finalize_response(
        &self,
        response: ErrorResponse,
        error: &Error,
        context: &ErrorContext,
    ) -> HttpResponse {
        // Populate the stack trace if enabled and not already set by a custom
        // transformer.
        let mut response = response;
        if self.include_stack_trace && response.stack_trace.is_none() {
            response = response.stack_trace(std::backtrace::Backtrace::force_capture().to_string());
        }

        // Call loggers
        for logger in &self.loggers {
            logger(error, context, &response);
        }

        response.into_http_response(self.format)
    }
}

impl Default for ErrorTransformer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ErrorTransformer {
    fn clone(&self) -> Self {
        Self {
            format: self.format,
            include_stack_trace: self.include_stack_trace,
            filter_sensitive: self.filter_sensitive,
            transformers: self.transformers.clone(),
            filters: self.filters.clone(),
            loggers: self.loggers.clone(),
            include_path: self.include_path,
            include_timestamp: self.include_timestamp,
            error_codes: self.error_codes.clone(),
            production_mode: self.production_mode,
        }
    }
}

// ============================================================================
// Preset Configurations
// ============================================================================

impl ErrorTransformer {
    /// Development configuration (verbose, includes stack traces).
    pub fn development() -> Self {
        Self::new()
            .production_mode(false)
            .include_stack_trace(true)
            .filter_sensitive_data(false)
            .with_logger(|error, ctx, _response| {
                eprintln!(
                    "[DEV ERROR] {} {} - {:?}",
                    ctx.request.method,
                    ctx.request.path_only(),
                    error
                );
            })
    }

    /// Production configuration (safe, minimal information).
    pub fn production() -> Self {
        Self::new()
            .production_mode(true)
            .include_stack_trace(false)
            .filter_sensitive_data(true)
            .with_logger(|error, ctx, response| {
                // Log to tracing
                if error.is_server_error() {
                    crate::logging::error!(
                        status = response.status,
                        path = %ctx.request.path_only(),
                        request_id = ctx.request_id,
                        error = %error.log_display(),
                        "Server error occurred"
                    );
                } else {
                    crate::logging::warn!(
                        status = response.status,
                        path = %ctx.request.path_only(),
                        request_id = ctx.request_id,
                        "Client error occurred"
                    );
                }
            })
    }

    /// API configuration (Problem Details format).
    pub fn api() -> Self {
        Self::new()
            .format(ResponseFormat::ProblemDetails)
            .production_mode(true)
            .filter_sensitive_data(true)
    }
}

// ============================================================================
// Error Response Builder
// ============================================================================

/// Builder for creating standardized error responses.
pub struct ErrorResponseBuilder {
    transformer: ErrorTransformer,
}

impl ErrorResponseBuilder {
    /// Create a new error response builder.
    pub fn new() -> Self {
        Self {
            transformer: ErrorTransformer::new(),
        }
    }

    /// Use a specific transformer.
    pub fn with_transformer(mut self, transformer: ErrorTransformer) -> Self {
        self.transformer = transformer;
        self
    }

    /// Create a bad request (400) response.
    pub fn bad_request(message: impl Into<String>) -> HttpResponse {
        let error = Error::BadRequest(message.into());
        ErrorTransformer::new().transform(&error, &HttpRequest::new("", ""))
    }

    /// Create an unauthorized (401) response.
    pub fn unauthorized(message: impl Into<String>) -> HttpResponse {
        let error = Error::Unauthorized(message.into());
        ErrorTransformer::new().transform(&error, &HttpRequest::new("", ""))
    }

    /// Create a forbidden (403) response.
    pub fn forbidden(message: impl Into<String>) -> HttpResponse {
        let error = Error::Forbidden(message.into());
        ErrorTransformer::new().transform(&error, &HttpRequest::new("", ""))
    }

    /// Create a not found (404) response.
    pub fn not_found(message: impl Into<String>) -> HttpResponse {
        let error = Error::NotFound(message.into());
        ErrorTransformer::new().transform(&error, &HttpRequest::new("", ""))
    }

    /// Create an internal server error (500) response.
    pub fn internal_error(message: impl Into<String>) -> HttpResponse {
        let error = Error::Internal(message.into());
        ErrorTransformer::new().transform(&error, &HttpRequest::new("", ""))
    }

    /// Create a validation error (422) response with field errors.
    pub fn validation_error(errors: Vec<ValidationError>) -> HttpResponse {
        let response = ErrorResponse::new(422)
            .message("Validation failed")
            .error_type("VALIDATION_ERROR")
            .with_validation_errors(errors);

        response.into_http_response(ResponseFormat::Json)
    }
}

impl Default for ErrorResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape a string for safe interpolation into HTML text content.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Apply `f` to the error's message payload, rebuilding the same variant so
/// the status code is preserved. `Io` carries no `String` payload and maps to
/// `Internal`, which shares its 500 status.
fn map_error_message(error: &Error, f: impl FnOnce(&str) -> String) -> Error {
    macro_rules! map_variants {
        ($($variant:ident),* $(,)?) => {
            match error {
                $(Error::$variant(msg) => Error::$variant(f(msg)),)*
                other => Error::Internal(f(&other.to_string())),
            }
        };
    }
    map_variants!(
        Http,
        RouteNotFound,
        MethodNotAllowed,
        DependencyInjection,
        ProviderNotFound,
        Serialization,
        Deserialization,
        Validation,
        Internal,
        Forbidden,
        BadRequest,
        Unauthorized,
        PaymentRequired,
        NotFound,
        NotAcceptable,
        ProxyAuthenticationRequired,
        RequestTimeout,
        Conflict,
        Gone,
        LengthRequired,
        PreconditionFailed,
        PayloadTooLarge,
        UriTooLong,
        UnsupportedMediaType,
        RangeNotSatisfiable,
        ExpectationFailed,
        ImATeapot,
        MisdirectedRequest,
        UnprocessableEntity,
        Locked,
        FailedDependency,
        TooEarly,
        UpgradeRequired,
        PreconditionRequired,
        TooManyRequests,
        RequestHeaderFieldsTooLarge,
        UnavailableForLegalReasons,
        NotImplemented,
        BadGateway,
        ServiceUnavailable,
        GatewayTimeout,
        HttpVersionNotSupported,
        VariantAlsoNegotiates,
        InsufficientStorage,
        LoopDetected,
        NotExtended,
        NetworkAuthenticationRequired,
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_response_new() {
        let response = ErrorResponse::new(404).message("Not found");
        assert_eq!(response.status, 404);
        assert_eq!(response.message, "Not found");
    }

    #[test]
    fn test_error_response_builder() {
        let response = ErrorResponse::new(400)
            .message("Bad request")
            .code("ERR_001")
            .details("Invalid input")
            .error_type("VALIDATION")
            .path("/api/users")
            .request_id("req-123");

        assert_eq!(response.status, 400);
        assert_eq!(response.code, Some("ERR_001".to_string()));
        assert_eq!(response.details, Some("Invalid input".to_string()));
    }

    #[test]
    fn test_validation_error() {
        let err = ValidationError::new("email", "Invalid email format")
            .rule("email")
            .value("not-an-email");

        assert_eq!(err.field, "email");
        assert_eq!(err.message, "Invalid email format");
        assert_eq!(err.rule, Some("email".to_string()));
    }

    #[test]
    fn test_error_response_with_validation_errors() {
        let response = ErrorResponse::new(422)
            .message("Validation failed")
            .with_validation_error(ValidationError::new("name", "Required"))
            .with_validation_error(ValidationError::new("email", "Invalid"));

        assert_eq!(response.validation_errors.len(), 2);
    }

    #[test]
    fn test_error_response_to_json() {
        let response = ErrorResponse::new(404).message("Not found");
        let json = response.to_json();
        assert!(json.contains("404"));
        assert!(json.contains("Not found"));
    }

    #[test]
    fn test_error_response_to_plain_text() {
        let response = ErrorResponse::new(404).message("Resource not found");
        let text = response.to_plain_text();
        assert!(text.contains("404"));
        assert!(text.contains("Resource not found"));
    }

    #[test]
    fn test_error_response_to_html() {
        let response = ErrorResponse::new(500).message("Server error");
        let html = response.to_html();
        assert!(html.contains("500"));
        assert!(html.contains("Server error"));
        assert!(html.contains("<html>"));
    }

    #[test]
    fn test_error_transformer_default() {
        let transformer = ErrorTransformer::new();
        let error = Error::NotFound("User not found".to_string());
        let request = HttpRequest::new("GET", "/users/123".to_string());

        let response = transformer.transform(&error, &request);
        assert_eq!(response.status, 404);
    }

    #[test]
    fn test_error_transformer_production_mode() {
        let transformer = ErrorTransformer::new().production_mode(true);
        let error = Error::Internal("Database connection failed".to_string());
        let request = HttpRequest::new("GET", "/api".to_string());

        let response = transformer.transform(&error, &request);
        assert_eq!(response.status, 500);
        // In production mode, internal errors should hide details
        let body = String::from_utf8(response.body.to_vec()).unwrap();
        assert!(body.contains("internal server error"));
    }

    #[test]
    fn test_error_transformer_with_custom_transformer() {
        let transformer = ErrorTransformer::new().with_transformer(|error, _ctx| {
            if matches!(error, Error::NotFound(_)) {
                Some(ErrorResponse::new(404).message("Custom not found message"))
            } else {
                None
            }
        });

        let error = Error::NotFound("test".to_string());
        let request = HttpRequest::new("GET", "/test".to_string());

        let response = transformer.transform(&error, &request);
        let body = String::from_utf8(response.body.to_vec()).unwrap();
        assert!(body.contains("Custom not found message"));
    }

    #[test]
    fn test_sensitive_data_filtering() {
        let transformer = ErrorTransformer::new().filter_sensitive_data(true);
        let error = Error::BadRequest("Invalid password=secret123 in request".to_string());
        let request = HttpRequest::new("POST", "/login".to_string());

        let response = transformer.transform(&error, &request);
        let body = String::from_utf8(response.body.to_vec()).unwrap();
        assert!(!body.contains("secret123"));
        assert!(body.contains("[FILTERED]"));
    }

    #[test]
    fn test_error_context() {
        let mut request = HttpRequest::new("GET", "/api".to_string());
        request
            .headers
            .insert("X-Request-Id", "req-456".to_string());

        let context = ErrorContext::from_request(request)
            .user_id("user-123")
            .with_data("operation", "fetch_users");

        assert_eq!(context.request_id, Some("req-456".to_string()));
        assert_eq!(context.user_id, Some("user-123".to_string()));
    }

    #[test]
    fn test_problem_details_format() {
        let response = ErrorResponse::new(404)
            .message("User not found")
            .error_type("https://api.example.com/errors/not-found")
            .path("/users/123");

        let json = response.to_problem_details();
        assert!(json.contains("type"));
        assert!(json.contains("title"));
        assert!(json.contains("status"));
    }

    #[test]
    fn test_response_format_content_type() {
        let response = ErrorResponse::new(400).message("Bad request");

        let http_response = response.clone().into_http_response(ResponseFormat::Json);
        assert_eq!(
            http_response.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );

        let http_response = response
            .clone()
            .into_http_response(ResponseFormat::PlainText);
        assert_eq!(
            http_response.headers.get("Content-Type"),
            Some(&"text/plain; charset=utf-8".to_string())
        );

        let http_response = response
            .clone()
            .into_http_response(ResponseFormat::ProblemDetails);
        assert_eq!(
            http_response.headers.get("Content-Type"),
            Some(&"application/problem+json".to_string())
        );

        let http_response = response.clone().into_http_response(ResponseFormat::JsonApi);
        assert_eq!(
            http_response.headers.get("Content-Type"),
            Some(&"application/vnd.api+json".to_string())
        );

        let http_response = response.clone().into_http_response(ResponseFormat::Aws);
        assert_eq!(
            http_response.headers.get("Content-Type"),
            Some(&"application/x-amz-json-1.1".to_string())
        );
    }

    #[test]
    fn test_json_api_format() {
        let response = ErrorResponse::new(422)
            .message("Validation failed")
            .code("VALIDATION_ERROR")
            .with_validation_error(ValidationError::new("email", "Invalid format"));

        let json = response.to_json_api();
        assert!(json.contains("errors"));
        assert!(json.contains("422"));
        assert!(json.contains("email"));
    }

    #[test]
    fn test_graphql_format() {
        let response = ErrorResponse::new(400)
            .message("Bad request")
            .code("BAD_REQUEST")
            .path("/graphql");

        let json = response.to_graphql();
        assert!(json.contains("errors"));
        assert!(json.contains("Bad request"));
        assert!(json.contains("extensions"));
    }

    #[test]
    fn test_google_format() {
        let response = ErrorResponse::new(400)
            .message("Invalid argument")
            .with_validation_error(ValidationError::new("name", "Required"));

        let json = response.to_google();
        assert!(json.contains("error"));
        assert!(json.contains("INVALID_ARGUMENT"));
        assert!(json.contains("400"));
    }

    #[test]
    fn test_aws_format() {
        let response = ErrorResponse::new(400)
            .message("Validation error")
            .request_id("req-123");

        let json = response.to_aws();
        assert!(json.contains("__type"));
        assert!(json.contains("ValidationException"));
        assert!(json.contains("req-123"));
    }

    #[test]
    fn test_azure_format() {
        let response = ErrorResponse::new(400)
            .message("Bad request")
            .code("InvalidInput")
            .path("/api/users")
            .with_validation_error(ValidationError::new("email", "Invalid"));

        let json = response.to_azure();
        assert!(json.contains("error"));
        assert!(json.contains("InvalidInput"));
        assert!(json.contains("details"));
    }

    #[test]
    fn test_error_code_mapping() {
        let transformer = ErrorTransformer::new()
            .map_error_code("NOT_FOUND", "ERR_404")
            .map_error_code("VALIDATION_ERROR", "ERR_422");

        assert!(transformer.error_codes.contains_key("NOT_FOUND"));
        assert_eq!(
            transformer.error_codes.get("NOT_FOUND"),
            Some(&"ERR_404".to_string())
        );
    }

    #[test]
    fn test_preset_development() {
        let transformer = ErrorTransformer::development();
        assert!(!transformer.production_mode);
        assert!(transformer.include_stack_trace);
    }

    #[test]
    fn test_preset_production() {
        let transformer = ErrorTransformer::production();
        assert!(transformer.production_mode);
        assert!(!transformer.include_stack_trace);
        assert!(transformer.filter_sensitive);
    }

    #[test]
    fn test_preset_api() {
        let transformer = ErrorTransformer::api();
        assert_eq!(transformer.format, ResponseFormat::ProblemDetails);
    }

    #[test]
    fn test_transform_preserves_status_of_unlisted_variants() {
        let transformer = ErrorTransformer::new();
        let request = HttpRequest::new("GET", "/test");

        let response = transformer.transform(&Error::TooManyRequests("slow down".into()), &request);
        assert_eq!(response.status, 429);

        let response = transformer.transform(&Error::Conflict("dup".into()), &request);
        assert_eq!(response.status, 409);

        let response = transformer.transform(&Error::ServiceUnavailable("down".into()), &request);
        assert_eq!(response.status, 503);
    }

    #[test]
    fn test_user_registered_filters_are_applied() {
        let transformer =
            ErrorTransformer::new().with_filter(|_| Error::NotFound("filtered by user".into()));
        let request = HttpRequest::new("GET", "/test");

        let response = transformer.transform(&Error::Internal("original".into()), &request);
        assert_eq!(response.status, 404);
        let body = String::from_utf8(response.into_body_bytes().to_vec()).unwrap();
        assert!(body.contains("filtered by user"));
    }

    #[test]
    fn test_to_html_escapes_message_and_details() {
        let response = ErrorResponse::new(400)
            .message("<script>alert(1)</script>")
            .details("a & b <img>");
        let html = response.to_html();
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("a &amp; b &lt;img&gt;"));
    }

    #[test]
    fn test_filter_sensitive_string_redacts_pii_and_secrets() {
        let transformer = ErrorTransformer::new().filter_sensitive_data(true);
        let input = "card 4111 1111 1111 1111 ssn 123-45-6789 \
                     email user@example.com token=abcdef123 password=hunter2 \
                     Bearer sk_live_secret";
        let filtered = transformer.filter_sensitive_string(input);

        // Card and SSN are redacted.
        assert!(filtered.contains("[CARD FILTERED]"));
        assert!(!filtered.contains("4111 1111 1111 1111"));
        assert!(filtered.contains("[SSN FILTERED]"));
        assert!(!filtered.contains("123-45-6789"));

        // Token / password / bearer secrets are redacted.
        assert!(!filtered.contains("abcdef123"));
        assert!(!filtered.contains("hunter2"));
        assert!(!filtered.contains("sk_live_secret"));
        assert!(filtered.contains("[FILTERED]"));

        // Non-secret email address is preserved (not part of the redaction set).
        assert!(filtered.contains("user@example.com"));
    }

    /// The widened key set: authorization schemes, basic credentials, PINs,
    /// OTPs, CVVs, SSNs, session ids, passwd and one-time codes, in form and
    /// JSON shapes -- without eating innocent words that contain them.
    #[test]
    fn test_redact_sensitive_widened_keys() {
        let cases = [
            "Authorization: Basic dXNlcjpodW50ZXIy",
            "authorization=Bearer s3cr3tv4l",
            "basic dXNlcjpodW50ZXIy",
            "pin=4821 otp=992211 cvv=737 ssn=078051120",
            "session_id=s3cr3tv4l passwd=s3cr3tv4l",
            "code=s3cr3tv4l&state=xyz",
            r#"{"pin":"4821","sms_otp":992211,"cvv":"737","ssn":"078051120"}"#,
            r#"{"session":"s3cr3tv4l","passwd":"s3cr3tv4l","verification_code":"s3cr3tv4l"}"#,
            r#"{"authorization":"Bearer s3cr3tv4l","card_cvc":"737"}"#,
        ];
        for input in cases {
            let out = redact_sensitive(input);
            for secret in [
                "dXNlcjpodW50ZXIy",
                "s3cr3tv4l",
                "4821",
                "992211",
                "737",
                "078051120",
            ] {
                assert!(!out.contains(secret), "{input} -> {out}");
            }
        }

        // Words that merely contain a short key stay readable.
        let benign =
            r#"shipping=ground spinner=on {"error_code":"E42","mapping":"x"} basic auth failed"#;
        assert_eq!(redact_sensitive(benign), benign);
    }

    /// Round-4 bypasses of the text path: whitespace before `=`, dotted and
    /// bracketed keys, and the added key names.
    #[test]
    fn test_redact_sensitive_round4_shapes() {
        for input in [
            "password = s3cr3tv4l",
            "token : s3cr3tv4l",
            "user[password]=s3cr3tv4l",
            "user%5Bpassword%5D=s3cr3tv4l",
            "user[pin]=s3cr3tv4l",
            r#"{"user.password":"s3cr3tv4l"}"#,
            r#"{"user[pin]":"s3cr3tv4l"}"#,
            "pass=s3cr3tv4l pw=s3cr3tv4l auth=s3cr3tv4l",
            "passphrase=s3cr3tv4l jwt=s3cr3tv4l signature=s3cr3tv4l",
            "cookie=s3cr3tv4l pin_code=s3cr3tv4l",
            r#"{"pass":"s3cr3tv4l","pw":"s3cr3tv4l","auth":"s3cr3tv4l","pin_code":"s3cr3tv4l"}"#,
            r#"{"passphrase":"s3cr3tv4l","jwt":"s3cr3tv4l","signature":"s3cr3tv4l"}"#,
            "card_number=s3cr3tv4l account_number=s3cr3tv4l iban=s3cr3tv4l pan=s3cr3tv4l",
            "passcode=s3cr3tv4l cc_num=s3cr3tv4l",
            r#"{"cardNumber":"s3cr3tv4l","iban":"s3cr3tv4l","card_pan":"s3cr3tv4l"}"#,
        ] {
            let out = redact_sensitive(input);
            assert!(!out.contains("s3cr3tv4l"), "{input} -> {out}");
        }
        // `pass` and `pw` are whole-key only.
        let benign = "bypass=1 compass=n span=2 expand=y company=x";
        assert_eq!(redact_sensitive(benign), benign);
    }

    /// Card numbers of every real length (13-19 digits) are redacted,
    /// grouped or not, when they pass the Luhn check; digit runs that fail it
    /// (order ids, timestamps) are left readable.
    #[test]
    fn test_redact_sensitive_card_lengths_and_luhn() {
        for (input, card) in [
            ("amex 378282246310005 declined", "378282246310005"),
            ("amex 3782 822463 10005 declined", "3782 822463 10005"),
            ("amex 3782-822463-10005", "3782-822463-10005"),
            ("visa 4111111111111111", "4111111111111111"),
            ("visa13 4222222222222", "4222222222222"),
            ("long 6304000000000000000", "6304000000000000000"),
            ("long 6304 0000 0000 0000 000", "6304 0000 0000 0000 000"),
            // A neighbouring number joined by a space must not hide the card.
            ("qty 2 4111 1111 1111 1111", "4111 1111 1111 1111"),
            ("4111 1111 1111 1111 12 units", "4111 1111 1111 1111"),
        ] {
            let out = redact_sensitive(input);
            assert!(!out.contains(card), "{input} -> {out}");
            assert!(out.contains("[CARD FILTERED]"), "{input} -> {out}");
        }
        // Fail Luhn: not a card.
        for benign in [
            "order 4111111111111112 shipped",
            "order 1234567890123 shipped",
            "ts 16983847261234567",
        ] {
            assert_eq!(redact_sensitive(benign), benign);
        }
        // Digits before a grouped card (a date, a phone number, an id) must
        // not let any of it through.
        for (input, card_tail) in [
            ("12 34 4111-1111-1111-1111", "1111-1111"),
            ("+1 555 4111 1111 1111 1111", "1111 1111"),
            ("id 1234 4111 1111 1111 1111", "1111 1111"),
            ("2026-10-30 4111 1111 1111 1111", "1111 1111"),
            ("ref 7 8 9 3782 822463 10005", "822463"),
            ("Order 98765 4111 1111 1111 1111 declined", "1111 1111"),
            ("ref-2026-4111-1111-1111-1111", "1111-1111"),
            ("10 20 4111 1111 1111 1111", "1111 1111"),
            ("ref4111111111111111", "111111111111"),
            ("cc_4111 1111 1111 1111", "1111 1111"),
        ] {
            let out = redact_sensitive(input);
            assert!(out.contains("[CARD FILTERED]"), "{input} -> {out}");
            assert!(!out.contains(card_tail), "{input} -> {out}");
            assert!(!out.contains("4111"), "{input} -> {out}");
        }
        // Other separators people type.
        for input in [
            "4111.1111.1111.1111",
            "4111  1111  1111  1111",
            "4111\u{A0}1111\u{A0}1111\u{A0}1111",
            "4111\t1111\t1111\t1111",
            "4111/1111/1111/1111",
            "4111 - 1111 - 1111 - 1111",
            "4111\u{2013}1111\u{2013}1111\u{2013}1111",
            "4111\u{3000}1111\u{3000}1111\u{3000}1111",
            "4111_1111_1111_1111",
            // Glued to its expiry, or to its CVV.
            "41111111111111111226",
            "4111111111111111123",
        ] {
            assert!(!redact_sensitive(input).contains("1111"), "{input:?}");
        }
        // Text with digits but no card comes back borrowed, unchanged.
        assert!(matches!(
            redact_sensitive("order 1500 shipped on 2026-10-30"),
            Cow::Borrowed(_)
        ));
        // A card typed in fullwidth digits is still a card.
        let fullwidth: String = "4111 1111 1111 1111"
            .chars()
            .map(|c| match c {
                '0'..='9' => char::from_u32(c as u32 - '0' as u32 + 0xFF10).unwrap(),
                other => other,
            })
            .collect();
        let input = format!("card {fullwidth}");
        let out = redact_sensitive(&input);
        assert_eq!(out, "card [CARD FILTERED]");
        // The surrounding text and a trailing non-card number survive.
        assert_eq!(
            redact_sensitive("qty 2 4111 1111 1111 1111 ok"),
            "qty 2 [CARD FILTERED] ok"
        );
    }

    #[test]
    fn test_is_sensitive_key() {
        for key in [
            "signing_key_pem",
            "hmacKeyHex",
            "master_key_b64",
            "key_material",
            "password",
            "user.password",
            "user[password]",
            "user[0][password]",
            "newPassword",
            "authToken",
            "apiKey",
            "x-api-key",
            "pass",
            "user_pass",
            "passphrase",
            "pw",
            "auth",
            "jwt",
            "id_token",
            "signature",
            "cookie",
            "pin_code",
            "pinCode",
            "otp",
            "sms-otp",
            "ssn",
            "one_time_code",
            "code_verifier",
            "client_secret",
            "session.id",
            // Segment-only names after a camelCase or other boundary.
            "newPin",
            "userPin",
            "smsOtp",
            "userSsn",
            "ssnLast4",
            "oldPw",
            "currentPass",
            "otpValue",
            "userMfaCode",
            "emailVerificationCode",
            "user:pin",
            "user/pin",
            "user__pin",
            "XMLToken",
            "OAuthCode",
            "TOTPCode",
            "APIKey",
            "user_2FACode",
            "user2Pin",
            // Payment and account identifiers.
            "card_number",
            "cardNumber",
            "cardnumber",
            "cc_num",
            "ccNumber",
            "pan",
            "card_pan",
            "account_number",
            "accountNumber",
            "iban",
            "payee_iban",
            "passcode",
            "devicePasscode",
            // Key material named `*_key`.
            "key",
            "accessKey",
            "signingKey",
            "encryptionKey",
            "masterKey",
            "clientKey",
            "secret_access_key",
        ] {
            assert!(is_sensitive_key(key), "{key}");
        }
        for key in [
            "user",
            "name",
            "email",
            "code",
            "error_code",
            "bypass",
            "compass",
            "author",
            "shipping",
            "spinner",
            "mapping",
            "opinion",
            "happiness",
            "Shipping",
            "pinned",
            "passenger",
            "compassion",
            "topology",
            "authority",
            "errorCode",
            "statusCode",
            "monkey",
            "keyboard",
            "turkey",
            "keys",
            "company",
            "panel",
            "span",
            "expand",
            "account",
            "card",
        ] {
            assert!(!is_sensitive_key(key), "{key}");
        }
    }

    /// The common case (nothing to redact) neither allocates nor runs the
    /// replacement passes.
    #[test]
    fn test_redact_sensitive_borrows_benign_input() {
        for benign in ["", "ab", "hello world", r#"{"user":"alice"}"#] {
            assert!(
                matches!(redact_sensitive(benign), Cow::Borrowed(_)),
                "{benign}"
            );
        }
        assert!(matches!(
            redact_sensitive("password=x"),
            Cow::Owned(ref s) if s == "password=[FILTERED]"
        ));
    }

    #[test]
    fn test_filter_sensitive_string_stable_across_calls() {
        // Exercises the once-compiled LazyLock regexes across repeated calls.
        let transformer = ErrorTransformer::new().filter_sensitive_data(true);
        let input = "password=secret123 token=deadbeef";
        let first = transformer.filter_sensitive_string(input);
        let second = transformer.filter_sensitive_string(input);
        assert_eq!(first, second);
        assert!(!first.contains("secret123"));
        assert!(!first.contains("deadbeef"));
    }

    /// M9: the request target is not echoed by default, and when it is, the
    /// query (which may hold tokens) never is.
    #[test]
    fn test_error_body_never_echoes_query() {
        let req = HttpRequest::new("GET", "/reset?token=secret-token".to_string());
        let err = Error::NotFound("missing".to_string());

        let body = ErrorTransformer::new().transform(&err, &req).body;
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("secret-token"), "{body}");
        assert!(!body.contains("/reset"), "path is off by default: {body}");

        let body = ErrorTransformer::new()
            .include_path(true)
            .transform(&err, &req)
            .body;
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("/reset"), "{body}");
        assert!(!body.contains("secret-token"), "{body}");
    }
}
