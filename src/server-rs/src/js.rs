//! JavaScript semantics the wire format depends on.
//!
//! The Bun server's limits, timestamps and escapes are defined by JavaScript
//! built-ins: a `string.length` counts UTF-16 code units, `Date.parse` accepts
//! what it accepts, `encodeURIComponent` escapes what it escapes. Anything a
//! client can observe has to come out the same here, so those built-ins are
//! reproduced in one place instead of approximated at each call site.

use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, TimeZone, Timelike, Utc};

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

fn digits(s: &str, n: usize) -> Option<(i64, &str)> {
    if s.len() < n || !s.as_bytes()[..n].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some((s[..n].parse().ok()?, &s[n..]))
}

fn utc_ms(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, ms: i64) -> Option<i64> {
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    // 24:00:00.000 is the one hour-24 spelling ECMAScript allows.
    if h > 24 || (h == 24 && (mi != 0 || s != 0 || ms != 0)) || mi > 59 || s > 59 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(y as i32, mo as u32, d as u32)?;
    let days = date.signed_duration_since(NaiveDate::from_ymd_opt(1970, 1, 1)?).num_days();
    Some(days * 86_400_000 + h * 3_600_000 + mi * 60_000 + s * 1000 + ms)
}

/// The ECMAScript date-time string format: `YYYY`, `YYYY-MM`, `YYYY-MM-DD`,
/// each optionally followed by `THH:mm`, `THH:mm:ss`, `THH:mm:ss.sss` and an
/// offset (`Z`, `+HH:mm`). A date-only form is UTC; a date-time with no offset
/// is local time, and this server runs in UTC.
fn parse_iso(input: &str) -> Option<i64> {
    let (sign, rest) = match input.as_bytes().first()? {
        b'+' => (1, &input[1..]),
        b'-' => (-1, &input[1..]),
        _ => (0, input),
    };
    let (year, mut rest) = if sign == 0 {
        digits(rest, 4)?
    } else {
        let (y, r) = digits(rest, 6)?;
        if sign == -1 && y == 0 {
            return None;
        }
        (y * sign, r)
    };
    let (mut month, mut day) = (1, 1);
    if let Some(r) = rest.strip_prefix('-') {
        let (m, r) = digits(r, 2)?;
        month = m;
        rest = r;
        if let Some(r) = rest.strip_prefix('-') {
            let (d, r) = digits(r, 2)?;
            day = d;
            rest = r;
        }
    }
    if rest.is_empty() {
        return utc_ms(year, month, day, 0, 0, 0, 0);
    }
    let rest = rest.strip_prefix('T').or_else(|| rest.strip_prefix('t'))?;
    let (hour, rest) = digits(rest, 2)?;
    let rest = rest.strip_prefix(':')?;
    let (minute, mut rest) = digits(rest, 2)?;
    let (mut second, mut millis) = (0, 0);
    if let Some(r) = rest.strip_prefix(':') {
        let (s, r) = digits(r, 2)?;
        second = s;
        rest = r;
        if let Some(r) = rest.strip_prefix('.').or_else(|| rest.strip_prefix(',')) {
            let count = r.bytes().take_while(u8::is_ascii_digit).count();
            if count == 0 {
                return None;
            }
            let fraction = format!("{:0<3}", &r[..count.min(3)]);
            millis = fraction.parse().ok()?;
            rest = &r[count..];
        }
    }
    let offset_minutes = match rest {
        "" => 0,
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (oh, r) = digits(&rest[1..], 2)?;
            let r = r.strip_prefix(':').unwrap_or(r);
            let (om, r) = if r.is_empty() { (0, r) } else { digits(r, 2)? };
            if !r.is_empty() || oh > 23 || om > 59 {
                return None;
            }
            sign * (oh * 60 + om)
        }
    };
    Some(utc_ms(year, month, day, hour, minute, second, millis)? - offset_minutes * 60_000)
}

fn month_from_name(word: &str) -> Option<i64> {
    let lower = word.to_ascii_lowercase();
    if lower.len() < 3 {
        return None;
    }
    MONTHS
        .iter()
        .position(|m| lower.starts_with(&m.to_ascii_lowercase()))
        .map(|i| i as i64 + 1)
}

/// The legacy formats `Date.parse` falls back to, as far as real clients send
/// them: RFC 2822 / `toUTCString()` (`Sat, 21 Nov 2026 05:53:08 GMT`,
/// `21 Nov 2026 05:53:08 +0100`) and `toString()`-style
/// (`Nov 21 2026 05:53:08 GMT+0100`, `November 21, 2026`).
fn parse_legacy(input: &str) -> Option<i64> {
    let cleaned: String = input
        .chars()
        .map(|c| if c == ',' { ' ' } else { c })
        .collect();
    // Drop a trailing parenthesized zone name such as "(Coordinated Universal Time)".
    let cleaned = match cleaned.find('(') {
        Some(at) => cleaned[..at].to_string(),
        None => cleaned,
    };
    let mut words: Vec<&str> = cleaned.split_whitespace().collect();
    if words.is_empty() {
        return None;
    }
    // A leading weekday name carries no information.
    if words[0].len() >= 3
        && WEEKDAYS
            .iter()
            .any(|d| words[0].to_ascii_lowercase().starts_with(&d.to_ascii_lowercase()))
        && month_from_name(words[0]).is_none()
    {
        words.remove(0);
    }
    let (mut day, mut month, mut year) = (None, None, None);
    let mut time: Option<(i64, i64, i64)> = None;
    let mut offset_minutes: Option<i64> = None;
    let mut pm: Option<bool> = None;
    for word in words {
        let upper = word.to_ascii_uppercase();
        if word.contains(':') && time.is_none() {
            let (clock, zone) = match word.find(|c| c == '+' || c == '-') {
                Some(at) => (&word[..at], Some(&word[at..])),
                None => (word, None),
            };
            let parts: Vec<&str> = clock.split(':').collect();
            if parts.len() < 2 || parts.len() > 3 {
                return None;
            }
            let h = parts[0].parse().ok()?;
            let m = parts[1].parse().ok()?;
            let s = if parts.len() == 3 { parts[2].parse().ok()? } else { 0 };
            time = Some((h, m, s));
            if let Some(zone) = zone {
                offset_minutes = Some(parse_zone_offset(zone)?);
            }
        } else if upper == "AM" || upper == "PM" {
            pm = Some(upper == "PM");
        } else if upper == "GMT" || upper == "UTC" || upper == "UT" || upper == "Z" {
            offset_minutes.get_or_insert(0);
        } else if let Some(zone) = upper
            .strip_prefix("GMT")
            .or_else(|| upper.strip_prefix("UTC"))
            .filter(|rest| rest.starts_with('+') || rest.starts_with('-'))
        {
            offset_minutes = Some(parse_zone_offset(zone)?);
        } else if (word.starts_with('+') || word.starts_with('-')) && time.is_some() {
            offset_minutes = Some(parse_zone_offset(word)?);
        } else if let Some(m) = month_from_name(word) {
            if month.is_some() {
                return None;
            }
            month = Some(m);
        } else if word.bytes().all(|b| b.is_ascii_digit()) {
            let n: i64 = word.parse().ok()?;
            if word.len() >= 3 || (day.is_some() && year.is_none()) {
                if year.is_some() {
                    return None;
                }
                year = Some(n);
            } else if day.is_none() {
                day = Some(n);
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    let (mut h, mi, s) = time.unwrap_or((0, 0, 0));
    if let Some(pm) = pm {
        if !(1..=12).contains(&h) {
            return None;
        }
        h = h % 12 + if pm { 12 } else { 0 };
    }
    let mut year = year?;
    if (0..50).contains(&year) {
        year += 2000;
    } else if (50..100).contains(&year) {
        year += 1900;
    }
    let ms = utc_ms(year, month?, day?, h, mi, s, 0)?;
    Some(ms - offset_minutes.unwrap_or(0) * 60_000)
}

fn parse_zone_offset(zone: &str) -> Option<i64> {
    let sign = match zone.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let body: String = zone[1..].chars().filter(|c| *c != ':').collect();
    if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (h, m) = match body.len() {
        1 | 2 => (body.parse::<i64>().ok()?, 0),
        3 => (body[..1].parse().ok()?, body[1..].parse().ok()?),
        4 => (body[..2].parse().ok()?, body[2..].parse().ok()?),
        _ => return None,
    };
    Some(sign * (h * 60 + m))
}

/// `Date.parse(input)`: milliseconds since the epoch, or `None` for NaN.
///
/// Covers the ECMAScript format and the RFC 2822 / `Date.prototype.toString`
/// shapes. JavaScriptCore accepts further legacy spellings that no client of
/// this API sends; those read as invalid here.
pub fn date_parse(input: &str) -> Option<i64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let ms = parse_iso(trimmed).or_else(|| parse_legacy(trimmed))?;
    // ECMAScript's time range is ±8.64e15 ms around the epoch.
    (ms.abs() <= 8_640_000_000_000_000).then_some(ms)
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

/// `String(number)` for the values this server formats: integers print
/// without a fraction, everything else as the shortest round-trip decimal.
pub fn number_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if value == value.trunc() && value.abs() < 1e21 {
        return format!("{}", value as i128);
    }
    let mut buffer = ryu_like(value);
    if let Some(stripped) = buffer.strip_suffix(".0") {
        buffer = stripped.to_string();
    }
    buffer
}

fn ryu_like(value: f64) -> String {
    // `{}` on f64 is the shortest representation that round-trips, which is
    // also what ECMAScript's Number::toString produces for ordinary magnitudes.
    format!("{value}")
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
