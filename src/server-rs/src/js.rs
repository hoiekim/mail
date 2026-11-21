//! JavaScript semantics the wire format depends on.
//!
//! The Bun server's limits, timestamps and escapes are defined by JavaScript
//! built-ins: a `string.length` counts UTF-16 code units, `Date.parse` accepts
//! what it accepts, `encodeURIComponent` escapes what it escapes. Anything a
//! client can observe has to come out the same here, so those built-ins are
//! reproduced in one place instead of approximated at each call site.

use chrono::{DateTime, Datelike, SecondsFormat, TimeZone, Timelike, Utc};

/// `string.length`: the number of UTF-16 code units.
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `string.slice(start, end)` for non-negative indexes, counted in UTF-16
/// code units. A cut through the middle of a surrogate pair drops the half
/// that is left, where JavaScript would keep a lone surrogate.
pub fn utf16_slice(s: &str, start: usize, end: usize) -> String {
    if start == 0 && utf16_len(s) <= end {
        return s.to_string();
    }
    let units: Vec<u16> = s.encode_utf16().collect();
    let end = end.min(units.len());
    if start >= end {
        return String::new();
    }
    char::decode_utf16(units[start..end].iter().copied())
        .filter_map(Result::ok)
        .collect()
}

/// `string.slice(0, end)`.
pub fn utf16_truncate(s: &str, end: usize) -> String {
    utf16_slice(s, 0, end)
}

fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
            | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `string.trim()`: JavaScript's whitespace set, which includes the byte
/// order mark and excludes U+0085.
pub fn trim(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// `Date.now()`.
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// `new Date(ms).toISOString()`, e.g. `2026-11-21T05:53:08.123Z`.
pub fn iso_from_ms(ms: i64) -> String {
    iso_string(&Utc.timestamp_millis_opt(ms).single().unwrap_or_default())
}

/// `date.toISOString()`: millisecond precision, truncated, always `Z`.
pub fn iso_string(date: &DateTime<Utc>) -> String {
    date.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// `new Date().toISOString()`.
pub fn now_iso() -> String {
    iso_string(&Utc::now())
}

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `date.toUTCString()`, e.g. `Sat, 21 Nov 2026 05:53:08 GMT` — the format of
/// `Expires`, `Last-Modified` and `Date`.
pub fn utc_string(date: &DateTime<Utc>) -> String {
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[date.weekday().num_days_from_monday() as usize],
        date.day(),
        MONTHS[date.month0() as usize],
        date.year(),
        date.hour(),
        date.minute(),
        date.second()
    )
}

/// `Date.parse(input)`: milliseconds since the epoch, or `None` for NaN.
///
/// Bun's `Date.parse` is lenient well beyond the ECMAScript format
/// (`"5"` is 1 May 2001, `1-Jan-2026` is a date). The exact rules live with
/// the IMAP date handling, where they were verified against the Bun runtime
/// on thousands of inputs.
pub fn date_parse(input: &str) -> Option<i64> {
    crate::imap::util::date_parse(input)
}

fn is_uri_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte)
}

/// `encodeURIComponent(value)`.
pub fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_uri_unreserved(byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|d| d as u8)
}

/// `decodeURIComponent(value)`, or `None` where JavaScript throws `URIError`:
/// a `%` not followed by two hex digits, or escapes that are not valid UTF-8.
pub fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if !bytes.contains(&b'%') {
        return Some(value.to_string());
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let hi = hex_value(*bytes.get(i + 1)?)?;
        let lo = hex_value(*bytes.get(i + 2)?)?;
        let first = hi << 4 | lo;
        i += 3;
        if first < 0x80 {
            out.push(first);
            continue;
        }
        // A multi-byte sequence must be spelled entirely with escapes.
        let extra = match first {
            0xC2..=0xDF => 1,
            0xE0..=0xEF => 2,
            0xF0..=0xF4 => 3,
            _ => return None,
        };
        let mut sequence = vec![first];
        for _ in 0..extra {
            if bytes.get(i) != Some(&b'%') {
                return None;
            }
            let hi = hex_value(*bytes.get(i + 1)?)?;
            let lo = hex_value(*bytes.get(i + 2)?)?;
            sequence.push(hi << 4 | lo);
            i += 3;
        }
        std::str::from_utf8(&sequence).ok()?;
        out.extend_from_slice(&sequence);
    }
    String::from_utf8(out).ok()
}

/// `Number(value)` for a string: whitespace is trimmed, an empty string is 0,
/// and anything that is not a complete numeric literal is NaN.
pub fn number_from_str(value: &str) -> f64 {
    let trimmed = value.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if trimmed.is_empty() {
        return 0.0;
    }
    let lower = trimmed.to_ascii_lowercase();
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return match u64::from_str_radix(rest, radix) {
                Ok(n) if !rest.is_empty() => n as f64,
                _ => f64::NAN,
            };
        }
    }
    match trimmed {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    // Rust's parser also accepts "inf", "nan" and "infinity", which JavaScript does not.
    let numeric = trimmed
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'));
    if !numeric || !trimmed.bytes().any(|b| b.is_ascii_digit()) {
        return f64::NAN;
    }
    trimmed.parse().unwrap_or(f64::NAN)
}

/// `String(number)`: integers print without a fraction, large and small
/// magnitudes in exponent form (`1e+21`), everything else as the shortest
/// decimal that round-trips.
pub fn number_to_string(value: f64) -> String {
    crate::imap::types::js_number_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_units() {
        assert_eq!(utf16_len("aé😀"), 4);
        assert_eq!(utf16_slice("aé😀b", 0, 2), "aé");
        assert_eq!(utf16_slice("aé😀b", 2, 4), "😀");
        assert_eq!(utf16_truncate("abc", 10), "abc");
    }

    #[test]
    fn date_formats() {
        let date = Utc.with_ymd_and_hms(2026, 11, 21, 5, 53, 8).unwrap();
        assert_eq!(utc_string(&date), "Sat, 21 Nov 2026 05:53:08 GMT");
        assert_eq!(iso_string(&date), "2026-11-21T05:53:08.000Z");
    }

    #[test]
    fn parses_iso_dates() {
        assert_eq!(date_parse("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(date_parse("1970-01-01"), Some(0));
        assert_eq!(date_parse("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(date_parse("2026-11-21T05:53:08.123456Z"), Some(1795240388123));
        assert_eq!(date_parse("2026"), Some(1767225600000));
        assert_eq!(date_parse("garbage"), None);
        assert_eq!(date_parse(""), None);
        assert_eq!(date_parse("2026-13-01"), None);
    }

    #[test]
    fn parses_legacy_dates() {
        assert_eq!(date_parse("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(date_parse("Sat, 21 Nov 2026 05:53:08 GMT"), Some(1795240388000));
        assert_eq!(date_parse("21 Nov 2026 06:53:08 +0100"), Some(1795240388000));
    }

    #[test]
    fn uri_components() {
        assert_eq!(encode_uri_component("s:a.b+c/d="), "s%3Aa.b%2Bc%2Fd%3D");
        assert_eq!(decode_uri_component("a%20b%2F").as_deref(), Some("a b/"));
        assert_eq!(decode_uri_component("%E2%9C%93").as_deref(), Some("✓"));
        assert_eq!(decode_uri_component("%E0%A4%A"), None);
        assert_eq!(decode_uri_component("%"), None);
        assert_eq!(decode_uri_component("%zz"), None);
        assert_eq!(decode_uri_component("%ff"), None);
    }

    #[test]
    fn numbers() {
        assert_eq!(number_from_str(" 12 "), 12.0);
        assert_eq!(number_from_str(""), 0.0);
        assert!(number_from_str("12abc").is_nan());
        assert!(number_from_str("nan").is_nan());
        assert_eq!(number_from_str("0x10"), 16.0);
        assert_eq!(number_to_string(3.0), "3");
        assert_eq!(number_to_string(0.5), "0.5");
    }
}

/// `JSON.parse(text)`, or `None` where it throws.
///
/// `serde_json` alone is stricter than JavaScript in ways a client can reach:
/// it refuses a number too large for a double (JavaScript reads `Infinity`),
/// an escaped lone surrogate, and nesting past 128 levels. This parser takes
/// what JavaScript takes. An integral number is stored as an integer so it
/// prints without a fraction, as JavaScript prints it; a number outside the
/// double range, which JSON cannot carry, is stored as `null`. Nesting is
/// capped far above anything a client sends, to keep stack use bounded.
pub fn json_parse(text: &str) -> Option<serde_json::Value> {
    let mut parser = JsonParser { bytes: text.as_bytes(), at: 0 };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    (parser.at == parser.bytes.len()).then_some(value)
}

const JSON_MAX_DEPTH: usize = 4096;

struct JsonParser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &str, value: serde_json::Value) -> Option<serde_json::Value> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Some(value)
        } else {
            None
        }
    }

    fn value(&mut self, depth: usize) -> Option<serde_json::Value> {
        use serde_json::Value;
        if depth > JSON_MAX_DEPTH {
            return None;
        }
        match self.peek()? {
            b'{' => {
                self.at += 1;
                let mut map = serde_json::Map::new();
                self.skip_whitespace();
                if self.peek()? == b'}' {
                    self.at += 1;
                    return Some(Value::Object(map));
                }
                loop {
                    self.skip_whitespace();
                    if self.peek()? != b'"' {
                        return None;
                    }
                    let key = self.string()?;
                    self.skip_whitespace();
                    if self.peek()? != b':' {
                        return None;
                    }
                    self.at += 1;
                    self.skip_whitespace();
                    let value = self.value(depth + 1)?;
                    map.insert(key, value);
                    self.skip_whitespace();
                    match self.peek()? {
                        b',' => self.at += 1,
                        b'}' => {
                            self.at += 1;
                            return Some(Value::Object(map));
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                self.skip_whitespace();
                if self.peek()? == b']' {
                    self.at += 1;
                    return Some(Value::Array(items));
                }
                loop {
                    self.skip_whitespace();
                    items.push(self.value(depth + 1)?);
                    self.skip_whitespace();
                    match self.peek()? {
                        b',' => self.at += 1,
                        b']' => {
                            self.at += 1;
                            return Some(Value::Array(items));
                        }
                        _ => return None,
                    }
                }
            }
            b'"' => self.string().map(Value::String),
            b't' => self.literal("true", Value::Bool(true)),
            b'f' => self.literal("false", Value::Bool(false)),
            b'n' => self.literal("null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<serde_json::Value> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek()? {
            b'0' => self.at += 1,
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).ok()?;
        let value: f64 = text.parse().ok()?;
        if !value.is_finite() {
            return Some(serde_json::Value::Null);
        }
        if value == value.trunc() && value.abs() <= 9_007_199_254_740_992.0 {
            return Some(serde_json::Value::from(value as i64));
        }
        serde_json::Number::from_f64(value).map(serde_json::Value::Number)
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.bytes.get(self.at..self.at + 4)?;
        let text = std::str::from_utf8(digits).ok()?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        self.at += 4;
        u32::from_str_radix(text, 16).ok()
    }

    fn string(&mut self) -> Option<String> {
        self.at += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self.peek()?;
            self.at += 1;
            match byte {
                b'"' => return String::from_utf8(out).ok(),
                0..=0x1f => return None,
                b'\\' => {
                    let escape = self.peek()?;
                    self.at += 1;
                    let ch = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let unit = self.hex4()?;
                            match unit {
                                0xD800..=0xDBFF => {
                                    // A high surrogate pairs with a following low one.
                                    let rewind = self.at;
                                    let low = if self.bytes[self.at..].starts_with(b"\\u") {
                                        self.at += 2;
                                        self.hex4()
                                    } else {
                                        None
                                    };
                                    match low {
                                        Some(low @ 0xDC00..=0xDFFF) => {
                                            let code = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                                            char::from_u32(code).unwrap_or('\u{fffd}')
                                        }
                                        _ => {
                                            self.at = rewind;
                                            '\u{fffd}'
                                        }
                                    }
                                }
                                0xDC00..=0xDFFF => '\u{fffd}',
                                unit => char::from_u32(unit).unwrap_or('\u{fffd}'),
                            }
                        }
                        _ => return None,
                    };
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                }
                byte => out.push(byte),
            }
        }
    }
}

#[cfg(test)]
mod json_tests {
    use super::json_parse;
    use serde_json::json;

    #[test]
    fn parses_what_javascript_parses() {
        assert_eq!(json_parse(r#"{"a":[1,2.5,"x",true,null]}"#), Some(json!({"a": [1, 2.5, "x", true, null]})));
        assert_eq!(json_parse(" [ ] "), Some(json!([])));
        assert_eq!(json_parse("1.0"), Some(json!(1)));
        assert_eq!(json_parse("1e3"), Some(json!(1000)));
        assert_eq!(json_parse(r#"{"a":1e400}"#), Some(json!({"a": null})));
        assert_eq!(json_parse(r#"{"a":"\ud800"}"#), Some(json!({"a": "\u{fffd}"})));
        assert_eq!(json_parse(r#""😀""#), Some(json!("😀")));
        assert_eq!(json_parse(r#"{"a":1,"b":2,"a":3}"#).unwrap().to_string(), r#"{"a":3,"b":2}"#);
    }

    #[test]
    fn nesting_far_beyond_serde_jsons_default_limit() {
        // The server runs with 16 MiB stacks; a test thread has 2 MiB.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let deep = format!("{}{}", "[".repeat(3000), "]".repeat(3000));
                assert!(json_parse(&deep).is_some());
                let too_deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
                assert!(json_parse(&too_deep).is_none());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn refuses_what_javascript_refuses() {
        for bad in ["", "{", r#"{"a":}"#, "[1,]", "{'a':1}", "01", "1.", "+1", "NaN", "tru", r#""\x""#, "[1] x", "\"a\nb\"", r#"{"a":1,}"#, ".5", "-"] {
            assert_eq!(json_parse(bad), None, "{bad:?}");
        }
    }
}
