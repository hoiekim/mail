//! DNS blocklist lookups (spam/dnsbl.ts).
//!
//! Layer 1: the connecting address is looked up in DNS blocklists. A listing
//! marks a known spam source.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use futures_util::future::{join_all, BoxFuture};
use hickory_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
};
use hickory_resolver::error::{ResolveError, ResolveErrorKind};
use hickory_resolver::proto::error::ProtoErrorKind;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::{Name, TokioAsyncResolver};
use serde::Serialize;

use crate::spam::types::DnsBlocklist;

/// Timeout for one blocklist query, in milliseconds.
const DNSBL_TIMEOUT_MS: u64 = 2000;

static DEFAULT_DNSBLS: LazyLock<Vec<DnsBlocklist>> = LazyLock::new(|| {
    vec![
        DnsBlocklist::new("zen.spamhaus.org", "Spamhaus ZEN", 40),
        DnsBlocklist::new("bl.spamcop.net", "SpamCop", 30),
        DnsBlocklist::new("b.barracudacentral.org", "Barracuda", 25),
    ]
});

/// The DNS blocklists asked by default (`DEFAULT_DNSBLS`): reputable and
/// widely used.
pub fn default_dnsbls() -> &'static [DnsBlocklist] {
    &DEFAULT_DNSBLS
}

/// Prefix a dual-stack listener puts in front of an IPv4 peer address.
const IPV4_MAPPED_PREFIX: &str = "::ffff:";

/// `/^\d+$/.test(part) && parseInt(part) <= 255`: decimal digits only, of any
/// length, so `007` and `0000255` are octets too.
fn is_octet(part: &str) -> bool {
    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let significant = part.trim_start_matches('0');
    significant.is_empty()
        || (significant.len() <= 3 && significant.parse::<u16>().is_ok_and(|value| value <= 255))
}

/// The dotted quad an address denotes, or `None` if it denotes none.
///
/// A listener bound without a host reports an IPv4 peer in the mapped form
/// `::ffff:198.51.100.7`, which no blocklist answers for. Unwrapping it is what
/// lets one host get the same verdict over either socket family.
///
/// The quad is returned as written, leading zeros included.
///
/// ```ignore
/// to_ipv4("::ffff:198.51.100.7"); // Some("198.51.100.7")
/// to_ipv4("2001:db8::1");         // None
/// ```
pub fn to_ipv4(ip: &str) -> Option<&str> {
    let mapped = ip
        .get(..IPV4_MAPPED_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(IPV4_MAPPED_PREFIX));
    let quad = if mapped { &ip[IPV4_MAPPED_PREFIX.len()..] } else { ip };
    let mut parts = 0;
    for part in quad.split('.') {
        parts += 1;
        if !is_octet(part) {
            return None;
        }
    }
    (parts == 4).then_some(quad)
}

/// Reverses a dotted quad for a blocklist query: `1.2.3.4` becomes `4.3.2.1`.
fn reverse_ip(ipv4: &str) -> String {
    let mut parts: Vec<&str> = ipv4.split('.').collect();
    parts.reverse();
    parts.join(".")
}

/// Whether a dotted quad is a private or local address, which no blocklist
/// carries: 127/8, 10/8, 172.16/12, 192.168/16 and link-local 169.254/16.
fn is_private_ip(ipv4: &str) -> bool {
    let parts: Vec<u32> =
        ipv4.split('.').map(|part| part.trim_start_matches('0').parse().unwrap_or(0)).collect();
    let (first, second) = (parts.first().copied().unwrap_or(0), parts.get(1).copied().unwrap_or(0));

    first == 127
        || first == 10
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 169 && second == 254)
}

/// Whether a blocklist response represents a real listing.
///
/// Major blocklists (Spamhaus, SpamCop, Barracuda) encode genuine listings as
/// `127.0.0.X` records. Anything in the `127.255.X.X` range is a warning that
/// the query was rejected — most commonly Spamhaus's open-resolver response,
/// returned when queries arrive via a public resolver. Treating those warnings
/// as listings flags every incoming mail as spam.
///
/// Reference: <https://www.spamhaus.org/zen/> (Return Codes).
pub fn is_real_listing<S: AsRef<str>>(addresses: &[S]) -> bool {
    addresses.iter().any(|address| address.as_ref().starts_with("127.0."))
}

/// What one blocklist said about an address: it listed it, cleared it, or never answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsblVerdict {
    Listed,
    Clean,
    Unknown,
}

impl DnsblVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsblVerdict::Listed => "listed",
            DnsblVerdict::Clean => "clean",
            DnsblVerdict::Unknown => "unknown",
        }
    }
}

/// DNS failures that mean "no such record" — how a blocklist spells "not listed".
const NOT_LISTED_DNS_CODES: [&str; 4] = ["ENOTFOUND", "ENODATA", "NOTFOUND", "NODATA"];

/// The verdict a blocklist's successful response carries.
///
/// A record came back, so the address is either listed or the response is one of
/// the warning codes [`is_real_listing`] rejects — a query the blocklist declined
/// to answer, which is not a clearance.
///
/// ```ignore
/// verdict_for_answer(&["127.0.0.2"]);       // Listed
/// verdict_for_answer(&["127.255.255.254"]); // Unknown — open-resolver warning
/// ```
pub fn verdict_for_answer<S: AsRef<str>>(addresses: &[S]) -> DnsblVerdict {
    if is_real_listing(addresses) {
        DnsblVerdict::Listed
    } else {
        DnsblVerdict::Unknown
    }
}

/// The verdict a failed blocklist query carries.
///
/// Only the no-such-record codes mean "not listed". A timeout carries no code,
/// and a refusal or server failure describes the resolver rather than the
/// address, so neither clears it.
///
/// ```ignore
/// verdict_for_dns_error(Some("ENOTFOUND")); // Clean
/// verdict_for_dns_error(Some("EREFUSED"));  // Unknown
/// verdict_for_dns_error(None);              // Unknown — the timeout path
/// ```
pub fn verdict_for_dns_error(code: Option<&str>) -> DnsblVerdict {
    match code {
        Some(code) if NOT_LISTED_DNS_CODES.contains(&code) => DnsblVerdict::Clean,
        _ => DnsblVerdict::Unknown,
    }
}

/// A failed DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLookupError {
    /// The code Node's resolver reports for this failure, such as `ENOTFOUND`
    /// or `ESERVFAIL`; `None` when the failure has none.
    pub code: Option<String>,
    pub message: String,
}

impl DnsLookupError {
    pub fn new(code: Option<&str>, message: impl Into<String>) -> DnsLookupError {
        DnsLookupError { code: code.map(str::to_string), message: message.into() }
    }
}

impl std::fmt::Display for DnsLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DnsLookupError {}

/// The DNS query a blocklist check makes: `dns.promises.resolve4`. Implemented
/// by [`SystemDnsLookup`] for the network and by a test for canned answers.
///
/// ```ignore
/// struct Listed;
/// impl DnsLookup for Listed {
///     fn resolve4<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DnsLookupError>> {
///         Box::pin(async { Ok(vec!["127.0.0.2".to_string()]) })
///     }
/// }
/// let result = check_dnsbls_using("198.51.100.7", default_dnsbls(), &Listed).await; // score 95
/// ```
pub trait DnsLookup: Send + Sync {
    /// The A records of `name` as dotted quads, or why there are none.
    fn resolve4<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DnsLookupError>>;
}

/// The code Node's resolver gives a failure, where one corresponds. (Bun's
/// folds an empty answer into `ENOTFOUND`; that and `ENODATA` both clear.)
fn node_code(error: &ResolveError) -> Option<&'static str> {
    let io_code = |error: &std::io::Error| match error.kind() {
        std::io::ErrorKind::ConnectionRefused => Some("ECONNREFUSED"),
        std::io::ErrorKind::TimedOut => Some("ETIMEOUT"),
        _ => None,
    };
    match error.kind() {
        ResolveErrorKind::NoRecordsFound { response_code, .. } => Some(match response_code {
            ResponseCode::NXDomain => "ENOTFOUND",
            ResponseCode::NoError => "ENODATA",
            ResponseCode::ServFail => "ESERVFAIL",
            ResponseCode::Refused => "EREFUSED",
            ResponseCode::FormErr => "EFORMERR",
            ResponseCode::NotImp => "ENOTIMP",
            // The Bun server's resolver reads the remaining codes of the
            // header's four bits as a failed server from 12 up, and below
            // that as an answer that happens to hold no address.
            ResponseCode::Unknown(12..=15) => "ESERVFAIL",
            _ => "ENODATA",
        }),
        ResolveErrorKind::Timeout => Some("ETIMEOUT"),
        ResolveErrorKind::Io(error) => io_code(error),
        ResolveErrorKind::Proto(error) => match error.kind() {
            ProtoErrorKind::Timeout => Some("ETIMEOUT"),
            ProtoErrorKind::Io(error) => io_code(error),
            _ => None,
        },
        _ => None,
    }
}

/// DNS over the network, through the system's name servers.
///
/// It asks the way the Bun server's resolver does: for the name as given,
/// never through the search list, without consulting the hosts file, and
/// without a cache — every mail asks the blocklists afresh.
/// `tests/golden/spam/resolver.json` records what that resolver made of a
/// scripted name server; `tests/spam_golden.rs` holds this one to it.
pub struct SystemDnsLookup {
    resolver: TokioAsyncResolver,
}

impl SystemDnsLookup {
    /// A resolver over the name servers of `/etc/resolv.conf`, or over
    /// `127.0.0.1` when the file is unreadable or names none.
    pub fn from_system_conf() -> SystemDnsLookup {
        match hickory_resolver::system_conf::read_system_conf() {
            Ok((config, options)) if !config.name_servers().is_empty() => {
                SystemDnsLookup::build(config, options)
            }
            _ => SystemDnsLookup::with_name_servers(&[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)]),
        }
    }

    /// A resolver over the given name servers, asked over UDP, then TCP for a
    /// truncated answer.
    pub fn with_name_servers(name_servers: &[SocketAddr]) -> SystemDnsLookup {
        let mut config = ResolverConfig::new();
        for address in name_servers {
            for protocol in [Protocol::Udp, Protocol::Tcp] {
                config.add_name_server(NameServerConfig::new(*address, protocol));
            }
        }
        SystemDnsLookup::build(config, ResolverOpts::default())
    }

    fn build(config: ResolverConfig, mut options: ResolverOpts) -> SystemDnsLookup {
        // The name servers are asked one at a time in the order given, and the
        // first one's "no such name" is the answer: which server is asked
        // decides the verdict when one of them is a public resolver a
        // blocklist refuses.
        let name_servers: Vec<NameServerConfig> = config
            .name_servers()
            .iter()
            .cloned()
            .map(|mut name_server| {
                name_server.trust_negative_responses = true;
                name_server
            })
            .collect();
        options.num_concurrent_reqs = 1;
        options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        options.cache_size = 0;
        options.use_hosts_file = false;
        // Every query is for an absolute name, so no search list is carried over.
        let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
        SystemDnsLookup { resolver: TokioAsyncResolver::tokio(config, options) }
    }
}

/// The characters the Bun server's resolver (c-ares) accepts in a name.
fn is_hostname_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'/' | b'*')
}

/// The labels the Bun server's resolver puts on the wire for a name, or
/// `None` for a name it refuses to ask: an empty label, a label over 63
/// bytes, a name over 255 characters, or a character outside
/// `[A-Za-z0-9-._/*]`. A backslash escapes the next character, or three
/// decimal digits naming a byte; one trailing dot is the root, not a label.
fn wire_labels(name: &str) -> Option<Vec<Vec<u8>>> {
    let mut labels: Vec<Vec<u8>> = vec![Vec::new()];
    let mut bytes = name.bytes();
    while let Some(byte) = bytes.next() {
        let literal = match byte {
            b'.' => {
                labels.push(Vec::new());
                continue;
            }
            b'\\' => {
                let escaped = bytes.next()?;
                if escaped.is_ascii_digit() {
                    let mut value = u32::from(escaped - b'0');
                    for _ in 0..2 {
                        let digit = bytes.next().filter(u8::is_ascii_digit)?;
                        value = value * 10 + u32::from(digit - b'0');
                    }
                    u8::try_from(value).ok()?
                } else {
                    escaped
                }
            }
            byte => byte,
        };
        if !is_hostname_byte(literal) {
            return None;
        }
        labels.last_mut()?.push(literal);
    }

    if labels.last().is_some_and(Vec::is_empty) {
        labels.pop();
    }
    if labels.len() == 1 && labels[0].is_empty() {
        // "." alone is the root.
        labels.clear();
    }
    if labels.iter().any(|label| label.is_empty() || label.len() > 63) {
        return None;
    }
    let length: usize = labels.iter().map(Vec::len).sum::<usize>() + labels.len().saturating_sub(1);
    (length <= 255).then_some(labels)
}

impl DnsLookup for SystemDnsLookup {
    fn resolve4<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DnsLookupError>> {
        Box::pin(async move {
            let Some(labels) = wire_labels(name) else {
                // The Bun server's resolver reports a name it cannot ask as not
                // found, which the blocklist check reads as "not listed". A
                // malformed blocklist hostname therefore clears every address
                // there, and has to here.
                return Err(DnsLookupError::new(Some("ENOTFOUND"), format!("queryA ENOTFOUND {name}")));
            };
            // Absolute, so the search list of resolv.conf never applies. A name
            // of 254 or 255 characters is one the Bun server's resolver sends
            // although DNS has no room for it; this one will not.
            let mut query =
                Name::from_labels(labels).map_err(|error| DnsLookupError::new(None, error.to_string()))?;
            query.set_fqdn(true);
            match self.resolver.ipv4_lookup(query).await {
                Ok(lookup) => {
                    let addresses: Vec<String> = lookup.iter().map(|address| address.to_string()).collect();
                    if addresses.is_empty() {
                        // An answer holding no A record, such as a bare CNAME.
                        Err(DnsLookupError::new(Some("ENODATA"), format!("queryA ENODATA {name}")))
                    } else {
                        Ok(addresses)
                    }
                }
                Err(error) => Err(DnsLookupError::new(node_code(&error), error.to_string())),
            }
        })
    }
}

/// The process-wide resolver, created from the system configuration on first use.
fn system_lookup() -> &'static SystemDnsLookup {
    static LOOKUP: OnceLock<SystemDnsLookup> = OnceLock::new();
    LOOKUP.get_or_init(SystemDnsLookup::from_system_conf)
}

/// Asks one blocklist about a dotted quad, giving up after
/// [`DNSBL_TIMEOUT_MS`] so a silent resolver cannot hold a delivery.
async fn check_dnsbl(ipv4: &str, dnsbl: &DnsBlocklist, lookup: &dyn DnsLookup) -> DnsblVerdict {
    let query = format!("{}.{}", reverse_ip(ipv4), dnsbl.hostname);
    match tokio::time::timeout(Duration::from_millis(DNSBL_TIMEOUT_MS), lookup.resolve4(&query)).await {
        Ok(Ok(addresses)) => verdict_for_answer(&addresses),
        Ok(Err(error)) => verdict_for_dns_error(error.code.as_deref()),
        // The timeout carries no code.
        Err(_) => verdict_for_dns_error(None),
    }
}

/// One blocklist's answer about an address, as the per-blocklist queries settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsblAnswer {
    Fulfilled {
        dnsbl: DnsBlocklist,
        verdict: DnsblVerdict,
    },
    /// The query failed outside the lookup itself; `reason` says how.
    Rejected {
        reason: String,
    },
}

/// What the blocklists said about an address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsblResult {
    /// Sum of the scores of the blocklists that list the address.
    pub score: i64,
    pub listed_in: Vec<DnsBlocklist>,
    /// `Listed in <name>` for each listing.
    pub reasons: Vec<String>,
    /// Whether every blocklist reached a verdict: the score is a verdict, not
    /// an absence of one.
    pub evaluated: bool,
}

/// Folds the per-blocklist answers into one result.
///
/// `score` is an OR over the answers — one listing is enough to score.
/// `evaluated` is an AND: it reports whether every blocklist reached a verdict,
/// so a caller that treats `score: 0` as authorization can tell a clearance
/// from an absence of one. An answer that never arrived withholds the signal
/// rather than supplying it, which is why a single `Unknown` or a rejected
/// query clears it. No answers at all is unevaluated: nothing was asked.
pub fn aggregate_verdicts(answers: &[DnsblAnswer]) -> DnsblResult {
    let mut result = DnsblResult { evaluated: !answers.is_empty(), ..Default::default() };

    for answer in answers {
        match answer {
            DnsblAnswer::Rejected { .. } | DnsblAnswer::Fulfilled { verdict: DnsblVerdict::Unknown, .. } => {
                result.evaluated = false;
            }
            DnsblAnswer::Fulfilled { dnsbl, verdict: DnsblVerdict::Listed } => {
                result.listed_in.push(dnsbl.clone());
                result.score += dnsbl.score;
                result.reasons.push(format!("Listed in {}", dnsbl.name));
            }
            DnsblAnswer::Fulfilled { verdict: DnsblVerdict::Clean, .. } => {}
        }
    }

    result
}

/// Checks an address against the given blocklists through the system
/// resolver; pass [`default_dnsbls`] for the default set.
///
/// `evaluated` reports whether the score is a verdict or an absence of one, so a
/// caller that treats a clean address as authorization can tell the two apart.
pub async fn check_dnsbls(ip: &str, dnsbls: &[DnsBlocklist]) -> DnsblResult {
    check_dnsbls_using(ip, dnsbls, system_lookup()).await
}

/// [`check_dnsbls`] through the given lookup. The blocklists are asked in
/// parallel, each bounded by its own timeout.
pub async fn check_dnsbls_using(ip: &str, dnsbls: &[DnsBlocklist], lookup: &dyn DnsLookup) -> DnsblResult {
    // An address outside IPv4 is one the blocklists cannot be asked about.
    let Some(ipv4) = to_ipv4(ip) else {
        return DnsblResult::default();
    };
    // A private or local address names no internet host, so no blocklist carries
    // it — "not listed" is a definite answer here, not a missing one.
    if is_private_ip(ipv4) {
        return DnsblResult { evaluated: true, ..Default::default() };
    }

    let answers = join_all(dnsbls.iter().map(|dnsbl| async move {
        DnsblAnswer::Fulfilled { dnsbl: dnsbl.clone(), verdict: check_dnsbl(ipv4, dnsbl, lookup).await }
    }))
    .await;

    aggregate_verdicts(&answers)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    use tokio::net::UdpSocket;

    use super::*;

    fn zen() -> DnsBlocklist {
        DnsBlocklist::new("zen.spamhaus.org", "Spamhaus ZEN", 40)
    }

    fn spamcop() -> DnsBlocklist {
        DnsBlocklist::new("bl.spamcop.net", "SpamCop", 30)
    }

    fn answered(dnsbl: DnsBlocklist, verdict: DnsblVerdict) -> DnsblAnswer {
        DnsblAnswer::Fulfilled { dnsbl, verdict }
    }

    fn threw() -> DnsblAnswer {
        DnsblAnswer::Rejected { reason: "query failed".into() }
    }

    // --- checkDnsbls ---

    #[tokio::test]
    async fn skips_private_ip_addresses() {
        for ip in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.1.1"] {
            let result = check_dnsbls(ip, default_dnsbls()).await;
            assert_eq!(result.score, 0, "{ip}");
            assert!(result.listed_in.is_empty(), "{ip}");
            assert!(result.reasons.is_empty(), "{ip}");
        }
    }

    #[tokio::test]
    async fn handles_invalid_ip_addresses_gracefully() {
        for ip in ["not-an-ip", "256.1.1.1", "1.2.3", "1.2.3.4.5", ""] {
            let result = check_dnsbls(ip, default_dnsbls()).await;
            assert_eq!(result.score, 0, "{ip}");
            assert!(result.listed_in.is_empty(), "{ip}");
        }
    }

    // The next three reach the network, as they do in the Bun suite. Each
    // uses a resolver of its own: a test's runtime ends with the test, and a
    // shared resolver would keep sockets that belong to an ended one.

    #[tokio::test]
    async fn uses_the_default_dnsbls_on_a_public_address() {
        // Cloudflare DNS (1.1.1.1) should not be on any blocklist.
        let result =
            check_dnsbls_using("1.1.1.1", default_dnsbls(), &SystemDnsLookup::from_system_conf()).await;
        assert_eq!(result.score, 0);
    }

    #[tokio::test]
    async fn aggregates_into_the_result_structure() {
        let result =
            check_dnsbls_using("8.8.8.8", default_dnsbls(), &SystemDnsLookup::from_system_conf()).await;
        assert!(result.score >= 0);
        assert_eq!(result.listed_in.len(), result.reasons.len());
    }

    #[tokio::test]
    async fn handles_dns_query_failures_gracefully() {
        let fake = [DnsBlocklist::new("invalid.nonexistent.dnsbl.local", "Fake DNSBL", 100)];
        let result = check_dnsbls_using("8.8.8.8", &fake, &SystemDnsLookup::from_system_conf()).await;
        assert_eq!(result.score, 0);
        assert!(result.listed_in.is_empty());
    }

    // --- toIpv4 ---

    #[test]
    fn to_ipv4_unwraps_the_ipv4_mapped_form_a_dual_stack_listener_reports() {
        assert_eq!(to_ipv4("::ffff:198.51.100.7"), Some("198.51.100.7"));
        assert_eq!(to_ipv4("::FFFF:203.0.113.5"), Some("203.0.113.5"));
    }

    #[test]
    fn to_ipv4_passes_a_plain_dotted_quad_through_unchanged() {
        assert_eq!(to_ipv4("198.51.100.7"), Some("198.51.100.7"));
        assert_eq!(to_ipv4("0.0.0.0"), Some("0.0.0.0"));
        assert_eq!(to_ipv4("255.255.255.255"), Some("255.255.255.255"));
    }

    #[test]
    fn to_ipv4_returns_none_for_an_address_that_denotes_no_ipv4_host() {
        for ip in
            ["2001:db8::1", "::1", "::ffff:2001:db8::1", "not-an-ip", "256.1.1.1", "1.2.3", "1.2.3.4.5", ""]
        {
            assert_eq!(to_ipv4(ip), None, "{ip}");
        }
    }

    // --- checkDnsbls evaluability ---

    #[tokio::test]
    async fn reports_an_address_outside_ipv4_as_unevaluated() {
        for ip in ["2001:db8::1", "not-an-ip", "1.2.3", ""] {
            let result = check_dnsbls(ip, default_dnsbls()).await;
            assert_eq!(result.score, 0, "{ip}");
            assert!(!result.evaluated, "{ip}");
        }
    }

    #[tokio::test]
    async fn reports_a_private_address_as_evaluated() {
        for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::ffff:10.0.0.1"] {
            let result = check_dnsbls(ip, default_dnsbls()).await;
            assert_eq!(result.score, 0, "{ip}");
            assert!(result.evaluated, "{ip}");
        }
    }

    #[tokio::test]
    async fn reports_an_empty_blocklist_set_as_unevaluated() {
        let result = check_dnsbls("198.51.100.7", &[]).await;
        assert_eq!(result.score, 0);
        assert!(!result.evaluated);
    }

    // --- aggregateVerdicts ---

    #[test]
    fn aggregate_reports_evaluated_when_every_blocklist_reached_a_verdict() {
        let result = aggregate_verdicts(&[
            answered(zen(), DnsblVerdict::Listed),
            answered(spamcop(), DnsblVerdict::Clean),
        ]);
        assert_eq!(result.score, 40);
        assert_eq!(result.listed_in, vec![zen()]);
        assert_eq!(result.reasons, vec!["Listed in Spamhaus ZEN"]);
        assert!(result.evaluated);
    }

    #[test]
    fn aggregate_withdraws_evaluated_when_one_blocklist_never_answered() {
        // A clearance from the others is not a clearance from the one that was
        // never asked. Reading this as evaluated hands the allowlist exemption to
        // a sender whose connection no blocklist has an opinion on.
        let result = aggregate_verdicts(&[
            answered(zen(), DnsblVerdict::Clean),
            answered(spamcop(), DnsblVerdict::Unknown),
        ]);
        assert_eq!(result.score, 0);
        assert!(!result.evaluated);
    }

    #[test]
    fn aggregate_keeps_a_listings_score_while_withdrawing_evaluated() {
        let result = aggregate_verdicts(&[
            answered(zen(), DnsblVerdict::Listed),
            answered(spamcop(), DnsblVerdict::Unknown),
        ]);
        assert_eq!(result.score, 40);
        assert!(!result.evaluated);
    }

    #[test]
    fn aggregate_withdraws_evaluated_when_a_query_rejected_instead_of_answering() {
        let result = aggregate_verdicts(&[answered(zen(), DnsblVerdict::Clean), threw()]);
        assert_eq!(result.score, 0);
        assert!(!result.evaluated);
    }

    #[test]
    fn aggregate_reports_an_empty_answer_set_as_unevaluated() {
        assert_eq!(
            aggregate_verdicts(&[]),
            DnsblResult { score: 0, listed_in: vec![], reasons: vec![], evaluated: false }
        );
    }

    #[test]
    fn aggregate_sums_every_listing_rather_than_stopping_at_the_first() {
        let result = aggregate_verdicts(&[
            answered(zen(), DnsblVerdict::Listed),
            answered(spamcop(), DnsblVerdict::Listed),
        ]);
        assert_eq!(result.score, 70);
        assert_eq!(result.listed_in, vec![zen(), spamcop()]);
        assert!(result.evaluated);
    }

    // --- isRealListing ---

    #[test]
    fn real_listing_treats_127_0_0_x_addresses_as_real_listings() {
        assert!(is_real_listing(&["127.0.0.2"])); // Spamhaus SBL
        assert!(is_real_listing(&["127.0.0.4"])); // Spamhaus CSS
        assert!(is_real_listing(&["127.0.0.10"])); // Spamhaus PBL
        assert!(is_real_listing(&["127.0.0.2", "127.0.0.10"]));
    }

    #[test]
    fn real_listing_ignores_open_resolver_warnings() {
        // Spamhaus returns these when the query arrives via a public resolver.
        // They are warnings, not listings — treating them as listings flags
        // every incoming mail as spam.
        for address in ["127.255.255.252", "127.255.255.253", "127.255.255.254", "127.255.255.255"] {
            assert!(!is_real_listing(&[address]), "{address}");
        }
    }

    #[test]
    fn real_listing_ignores_mixed_responses_that_contain_only_warnings() {
        assert!(!is_real_listing(&["127.255.255.252", "127.255.255.254"]));
    }

    #[test]
    fn real_listing_counts_when_at_least_one_listing_record_is_present() {
        // Defensive: if a response returns both a real listing code and a
        // warning code, the real listing wins.
        assert!(is_real_listing(&["127.0.0.2", "127.255.255.254"]));
    }

    #[test]
    fn real_listing_is_false_on_empty_results() {
        assert!(!is_real_listing::<&str>(&[]));
    }

    #[test]
    fn real_listing_ignores_responses_outside_127_0() {
        // Some ISPs and captive portals return a content address for NXDOMAIN.
        assert!(!is_real_listing(&["192.0.2.1"]));
        assert!(!is_real_listing(&["10.0.0.1"]));
    }

    // --- verdictForAnswer ---

    #[test]
    fn answer_reads_a_127_0_0_x_record_as_a_listing() {
        assert_eq!(verdict_for_answer(&["127.0.0.2"]), DnsblVerdict::Listed);
        assert_eq!(verdict_for_answer(&["127.0.0.10"]), DnsblVerdict::Listed);
        assert_eq!(verdict_for_answer(&["127.0.0.2", "127.255.255.254"]), DnsblVerdict::Listed);
    }

    #[test]
    fn answer_reads_an_open_resolver_warning_as_no_answer_never_as_a_clearance() {
        // Reading it as clean hands the allowlist exemption to any sender whose
        // query the blocklist refused to answer.
        assert_eq!(verdict_for_answer(&["127.255.255.254"]), DnsblVerdict::Unknown);
        assert_eq!(verdict_for_answer(&["127.255.255.252"]), DnsblVerdict::Unknown);
        assert_eq!(verdict_for_answer(&["127.255.255.252", "127.255.255.254"]), DnsblVerdict::Unknown);
    }

    #[test]
    fn answer_reads_a_hijacked_nxdomain_response_as_no_answer() {
        assert_eq!(verdict_for_answer(&["192.0.2.1"]), DnsblVerdict::Unknown);
        assert_eq!(verdict_for_answer::<&str>(&[]), DnsblVerdict::Unknown);
    }

    // --- verdictForDnsError ---

    #[test]
    fn dns_error_clears_the_address_only_on_a_no_such_record_code() {
        for code in ["ENOTFOUND", "ENODATA", "NOTFOUND", "NODATA"] {
            assert_eq!(verdict_for_dns_error(Some(code)), DnsblVerdict::Clean, "{code}");
        }
    }

    #[test]
    fn dns_error_withholds_a_verdict_when_the_resolver_failed_rather_than_answered() {
        for code in ["ETIMEOUT", "ESERVFAIL", "EREFUSED", "ECONNREFUSED"] {
            assert_eq!(verdict_for_dns_error(Some(code)), DnsblVerdict::Unknown, "{code}");
        }
    }

    #[test]
    fn dns_error_withholds_a_verdict_when_the_rejection_carries_no_code() {
        // The timeout rejects with no code, so this is the shape condition 2 of
        // the allowlist gate leads with.
        assert_eq!(verdict_for_dns_error(None), DnsblVerdict::Unknown);
        assert_eq!(verdict_for_dns_error(Some("")), DnsblVerdict::Unknown);
    }

    // --- DEFAULT_DNSBLS ---

    #[test]
    fn default_dnsbls_have_the_expected_structure() {
        assert!(!default_dnsbls().is_empty());
        for dnsbl in default_dnsbls() {
            assert!(!dnsbl.hostname.is_empty());
            assert!(!dnsbl.name.is_empty());
            assert!(dnsbl.score > 0);
        }
    }

    #[test]
    fn default_dnsbls_include_the_major_blocklists() {
        let hostnames: Vec<&str> = default_dnsbls().iter().map(|dnsbl| dnsbl.hostname.as_str()).collect();
        assert!(hostnames.contains(&"zen.spamhaus.org"));
        assert!(hostnames.contains(&"bl.spamcop.net"));
        assert_eq!(
            default_dnsbls(),
            [
                DnsBlocklist::new("zen.spamhaus.org", "Spamhaus ZEN", 40),
                DnsBlocklist::new("bl.spamcop.net", "SpamCop", 30),
                DnsBlocklist::new("b.barracudacentral.org", "Barracuda", 25),
            ]
        );
    }

    // --- Beyond the TypeScript suite: the lookup seam and the resolver ---

    /// Answers by query name and records what was asked.
    #[derive(Default)]
    struct Canned {
        answers: HashMap<String, Result<Vec<String>, DnsLookupError>>,
        delay: Duration,
        asked: Mutex<Vec<String>>,
    }

    impl Canned {
        fn answer(mut self, name: &str, addresses: &[&str]) -> Canned {
            self.answers.insert(name.to_string(), Ok(addresses.iter().map(|a| a.to_string()).collect()));
            self
        }

        fn fail(mut self, name: &str, code: Option<&str>) -> Canned {
            self.answers.insert(name.to_string(), Err(DnsLookupError::new(code, "failed")));
            self
        }
    }

    impl DnsLookup for Canned {
        fn resolve4<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<String>, DnsLookupError>> {
            Box::pin(async move {
                self.asked.lock().unwrap().push(name.to_string());
                tokio::time::sleep(self.delay).await;
                match self.answers.get(name) {
                    Some(answer) => answer.clone(),
                    None => Err(DnsLookupError::new(Some("ENOTFOUND"), format!("queryA ENOTFOUND {name}"))),
                }
            })
        }
    }

    #[tokio::test]
    async fn asks_each_blocklist_for_the_reversed_address() {
        let lookup = Canned::default();
        let result = check_dnsbls_using("198.51.100.7", default_dnsbls(), &lookup).await;
        assert_eq!(result, DnsblResult { evaluated: true, ..Default::default() });
        let mut asked = lookup.asked.lock().unwrap().clone();
        asked.sort();
        assert_eq!(
            asked,
            vec![
                "7.100.51.198.b.barracudacentral.org",
                "7.100.51.198.bl.spamcop.net",
                "7.100.51.198.zen.spamhaus.org",
            ]
        );
    }

    #[tokio::test]
    async fn scores_listings_in_blocklist_order_and_unwraps_a_mapped_address() {
        let lookup = Canned::default()
            .answer("7.100.51.198.zen.spamhaus.org", &["127.0.0.2", "127.0.0.4"])
            .answer("7.100.51.198.b.barracudacentral.org", &["127.0.0.2"]);
        let result = check_dnsbls_using("::FFFF:198.51.100.7", default_dnsbls(), &lookup).await;
        assert_eq!(result.score, 65);
        assert_eq!(result.reasons, vec!["Listed in Spamhaus ZEN", "Listed in Barracuda"]);
        assert_eq!(result.listed_in.len(), 2);
        assert!(result.evaluated);
    }

    #[tokio::test]
    async fn an_unanswered_blocklist_withholds_evaluated_but_not_the_score() {
        let lookup = Canned::default()
            .answer("7.100.51.198.zen.spamhaus.org", &["127.0.0.2"])
            .answer("7.100.51.198.bl.spamcop.net", &["127.255.255.254"])
            .fail("7.100.51.198.b.barracudacentral.org", Some("ESERVFAIL"));
        let result = check_dnsbls_using("198.51.100.7", default_dnsbls(), &lookup).await;
        assert_eq!(result.score, 40);
        assert!(!result.evaluated);

        let refused = Canned::default().fail("7.100.51.198.zen.spamhaus.org", None);
        let result = check_dnsbls_using("198.51.100.7", &[zen()], &refused).await;
        assert_eq!(result, DnsblResult::default());
    }

    #[tokio::test]
    async fn keeps_the_octets_as_written() {
        let lookup = Canned::default().answer("004.003.002.001.zen.spamhaus.org", &["127.0.0.2"]);
        let result = check_dnsbls_using("001.002.003.004", &[zen()], &lookup).await;
        assert_eq!(result.score, 40);
        // 010 is ten, not eight: the private check reads the octets as decimal.
        let result = check_dnsbls_using("010.1.2.3", &[zen()], &Canned::default()).await;
        assert!(result.evaluated);
        assert!(lookup.asked.lock().unwrap().len() == 1);
    }

    #[tokio::test]
    async fn asks_in_parallel_and_gives_up_after_the_timeout() {
        // Three lookups that never answer in time settle together at the
        // two-second timeout, not one after another.
        assert_eq!(DNSBL_TIMEOUT_MS, 2000);
        let lookup = Canned { delay: Duration::from_millis(DNSBL_TIMEOUT_MS + 3000), ..Default::default() };
        let started = Instant::now();
        let result = check_dnsbls_using("198.51.100.7", default_dnsbls(), &lookup).await;
        let elapsed = started.elapsed();
        assert_eq!(result, DnsblResult::default());
        assert!(elapsed >= Duration::from_millis(DNSBL_TIMEOUT_MS), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(DNSBL_TIMEOUT_MS + 1500), "{elapsed:?}");
        assert_eq!(lookup.asked.lock().unwrap().len(), 3);
    }

    #[test]
    fn names_go_on_the_wire_as_the_bun_servers_resolver_puts_them() {
        // Observed from Bun's resolver against a name server that logs its questions.
        let labels = |name: &str| {
            wire_labels(name).map(|labels| {
                labels.iter().map(|label| String::from_utf8_lossy(label).to_string()).collect::<Vec<_>>()
            })
        };
        let asked = |name: &str, expected: &[&str]| {
            assert_eq!(labels(name).as_deref(), Some(&words(expected)[..]), "{name}")
        };
        asked("4.3.2.1.zen.spamhaus.org", &["4", "3", "2", "1", "zen", "spamhaus", "org"]);
        asked("004.003.002.001.zen.test", &["004", "003", "002", "001", "zen", "test"]);
        asked("trailing.test.", &["trailing", "test"]);
        asked("7.100.51.198.", &["7", "100", "51", "198"]);
        asked("localhost", &["localhost"]);
        asked(".", &[]);
        asked("MiXeD.TeSt", &["MiXeD", "TeSt"]);
        asked("under_score.test", &["under_score", "test"]);
        asked("-dash.test", &["-dash", "test"]);
        asked("*.wild.test", &["*", "wild", "test"]);
        asked("a/b.test", &["a/b", "test"]);
        asked("back\\slash.test", &["backslash", "test"]);
        asked("escaped\\.dot.test", &["escaped.dot", "test"]);
        asked("\\065.test", &["A", "test"]);
        asked("a\\046b.test", &["a.b", "test"]);
        asked("a\\045b.test", &["a-b", "test"]);
        asked("a\\*b.test", &["a*b", "test"]);
        asked("abc.test\\.", &["abc", "test."]);
        asked("a.\\..b", &["a", ".", "b"]);
        let longest_label = "x".repeat(63);
        asked(&format!("{longest_label}.test"), &[longest_label.as_str(), "test"]);

        for refused in [
            "bad..test",
            "7.100.51.198..",
            "..",
            ".leading.test",
            "trailing.test..",
            "a b.test",
            "a@b.test",
            "a+b.test",
            "a:b.test",
            "ünï.test",
            "中文.test",
            "a\0b.test",
            "tab\t.test",
            "q\"uote.test",
            "a\\032b.test",
            "a\\@b.test",
            "a\\255b.test",
            "a\\256b.test",
            "a\\12.test",
            "test.a\\1",
            "abc.test\\",
            "a\\06a.test",
            "a\\\\b.test",
        ] {
            assert_eq!(labels(refused), None, "{refused}");
        }
        assert_eq!(labels(&format!("{}.test", "x".repeat(64))), None);

        // 255 characters are asked, 256 are not.
        let label = |length: usize| "a".repeat(length);
        let at_limit = [label(63), label(63), label(63), label(63)].join(".");
        assert_eq!(at_limit.len(), 255);
        assert_eq!(wire_labels(&at_limit).map(|labels| labels.len()), Some(4));
        assert_eq!(wire_labels(&format!("{at_limit}.")).map(|labels| labels.len()), Some(4));
        let over_limit = [label(63), label(63), label(63), label(62), label(1)].join(".");
        assert_eq!(over_limit.len(), 256);
        assert_eq!(wire_labels(&over_limit), None);
    }

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|word| word.to_string()).collect()
    }

    #[tokio::test]
    async fn a_name_that_cannot_be_asked_reads_as_not_listed() {
        // What the Bun server does with a malformed blocklist hostname: its
        // resolver reports ENOTFOUND without asking anyone.
        let lookup = SystemDnsLookup::with_name_servers(&["127.0.0.1:9".parse().unwrap()]);
        for hostname in ["bad..test", "has space.test", "bücher.test"] {
            let error = lookup.resolve4(&format!("7.100.51.198.{hostname}")).await.unwrap_err();
            assert_eq!(error.code.as_deref(), Some("ENOTFOUND"), "{hostname}");
            let result =
                check_dnsbls_using("198.51.100.7", &[DnsBlocklist::new(hostname, "Bad", 40)], &lookup).await;
            assert_eq!(result, DnsblResult { evaluated: true, ..Default::default() }, "{hostname}");
        }
    }

    #[test]
    fn octets_are_decimal_digit_runs_up_to_255() {
        for octet in ["0", "7", "007", "255", "0000000255", "00"] {
            assert!(is_octet(octet), "{octet}");
        }
        for octet in ["", "256", "1000", "99999999999999999999", "1a", "-1", "+1", " 1", "1 ", "٣"] {
            assert!(!is_octet(octet), "{octet}");
        }
    }

    /// A DNS server on a loopback UDP port that answers every A query from
    /// `answer`: a response code and the records to return.
    async fn name_server(
        answer: impl Fn(&str) -> Option<(u8, Vec<[u8; 4]>)> + Send + 'static,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else { return };
                let query = &buffer[..length];
                // The question starts after the 12-byte header: labels, type, class.
                let mut labels = Vec::new();
                let mut at = 12;
                while at < query.len() && query[at] != 0 {
                    let size = query[at] as usize;
                    labels.push(String::from_utf8_lossy(&query[at + 1..at + 1 + size]).to_string());
                    at += 1 + size;
                }
                let question_end = at + 5;
                let Some((rcode, records)) = answer(&labels.join(".")) else { continue };

                let mut response = Vec::new();
                response.extend_from_slice(&query[..2]);
                response.extend_from_slice(&[0x81, 0x80 | rcode]);
                response.extend_from_slice(&[0, 1]);
                response.extend_from_slice(&(records.len() as u16).to_be_bytes());
                response.extend_from_slice(&[0, 0, 0, 0]);
                response.extend_from_slice(&query[12..question_end]);
                for record in records {
                    response.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    response.extend_from_slice(&record);
                }
                let _ = socket.send_to(&response, peer).await;
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn the_resolver_reports_what_nodes_resolver_reports() {
        let (address, server) = name_server(|name| match name {
            "listed.example" => Some((0, vec![[127, 0, 0, 2], [127, 0, 0, 10]])),
            "nodata.example" => Some((0, vec![])),
            "nxdomain.example" => Some((3, vec![])),
            "servfail.example" => Some((2, vec![])),
            "refused.example" => Some((5, vec![])),
            _ => None,
        })
        .await;
        let lookup = SystemDnsLookup::with_name_servers(&[address]);

        let mut listed = lookup.resolve4("listed.example").await.unwrap();
        listed.sort();
        assert_eq!(listed, vec!["127.0.0.10", "127.0.0.2"]);
        // A trailing dot is the same absolute name.
        assert!(lookup.resolve4("listed.example.").await.is_ok());

        let code = |result: Result<Vec<String>, DnsLookupError>| result.unwrap_err().code;
        assert_eq!(code(lookup.resolve4("nodata.example").await).as_deref(), Some("ENODATA"));
        assert_eq!(code(lookup.resolve4("nxdomain.example").await).as_deref(), Some("ENOTFOUND"));
        assert_eq!(code(lookup.resolve4("servfail.example").await).as_deref(), Some("ESERVFAIL"));
        assert_eq!(code(lookup.resolve4("refused.example").await).as_deref(), Some("EREFUSED"));
        server.abort();
    }

    #[tokio::test]
    async fn the_resolver_drives_the_verdicts_end_to_end() {
        let (address, server) = name_server(|name| match name {
            "7.100.51.198.listed.test" => Some((0, vec![[127, 0, 0, 2]])),
            "7.100.51.198.warning.test" => Some((0, vec![[127, 255, 255, 254]])),
            "7.100.51.198.clean.test" => Some((3, vec![])),
            "7.100.51.198.nodata.test" => Some((0, vec![])),
            "7.100.51.198.servfail.test" => Some((2, vec![])),
            // silent.test never answers.
            _ => None,
        })
        .await;
        let lookup = SystemDnsLookup::with_name_servers(&[address]);
        let list = |host: &str, score: i64| DnsBlocklist::new(host, host, score);

        let result =
            check_dnsbls_using("198.51.100.7", &[list("listed.test", 40), list("clean.test", 30)], &lookup)
                .await;
        assert_eq!(result.score, 40);
        assert_eq!(result.reasons, vec!["Listed in listed.test"]);
        assert!(result.evaluated);

        let result =
            check_dnsbls_using("198.51.100.7", &[list("clean.test", 30), list("nodata.test", 25)], &lookup)
                .await;
        assert_eq!(result, DnsblResult { evaluated: true, ..Default::default() });

        for unanswered in ["warning.test", "servfail.test"] {
            let result =
                check_dnsbls_using("198.51.100.7", &[list("clean.test", 30), list(unanswered, 25)], &lookup)
                    .await;
            assert_eq!(result, DnsblResult::default(), "{unanswered}");
        }

        let started = Instant::now();
        let result =
            check_dnsbls_using("198.51.100.7", &[list("listed.test", 40), list("silent.test", 25)], &lookup)
                .await;
        assert_eq!(result.score, 40);
        assert!(!result.evaluated);
        assert!(started.elapsed() >= Duration::from_millis(DNSBL_TIMEOUT_MS - 100));
        assert!(started.elapsed() < Duration::from_millis(DNSBL_TIMEOUT_MS + 1500));
        server.abort();
    }
}
