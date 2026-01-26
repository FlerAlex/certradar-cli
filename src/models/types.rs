use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// Certificate Transparency Types
// ============================================================================

/// Certificate from crt.sh search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    #[serde(rename = "crtsh_id")]
    pub crtsh_id: i64,
    #[serde(rename = "common_name")]
    pub common_name: String,
    #[serde(rename = "name_value")]
    pub name_value: String,
    #[serde(rename = "issuer_name")]
    pub issuer_name: String,
    #[serde(rename = "not_before")]
    pub not_before: String,
    #[serde(rename = "not_after")]
    pub not_after: String,
    #[serde(rename = "serial_number")]
    pub serial_number: String,
}

/// Detailed certificate info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDetail {
    #[serde(rename = "crtsh_id")]
    pub crtsh_id: i64,
    #[serde(rename = "common_name")]
    pub common_name: String,
    #[serde(rename = "name_value")]
    pub name_value: String,
    #[serde(rename = "issuer_name")]
    pub issuer_name: String,
    #[serde(rename = "not_before")]
    pub not_before: String,
    #[serde(rename = "not_after")]
    pub not_after: String,
    #[serde(rename = "serial_number")]
    pub serial_number: String,
    #[serde(rename = "signature_algo", skip_serializing_if = "Option::is_none")]
    pub signature_algo: Option<String>,
    #[serde(rename = "key_type", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(rename = "key_size", skip_serializing_if = "Option::is_none")]
    pub key_size: Option<i32>,
    #[serde(rename = "subject_alt_names")]
    pub subject_alt_names: Vec<String>,
    #[serde(rename = "issuer_cn", skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    #[serde(rename = "issuer_o", skip_serializing_if = "Option::is_none")]
    pub issuer_o: Option<String>,
}

/// Search result response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub certificates: Vec<Certificate>,
    pub total: usize,
    pub source: String,
}

// ============================================================================
// SSL Analyzer Types
// ============================================================================

/// SSL/TLS analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslAnalysisResult {
    pub host: String,
    pub port: u16,
    pub protocols: ProtocolSupport,
    pub certificate: SslCertificateInfo,
    #[serde(rename = "cipherSuites")]
    pub cipher_suites: Vec<CipherSuiteInfo>,
    #[serde(rename = "securityGrade")]
    pub security_grade: String,
    pub issues: Vec<SecurityIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsts: Option<HstsInfo>,
    #[serde(rename = "ocspStapling", skip_serializing_if = "Option::is_none")]
    pub ocsp_stapling: Option<OcspStaplingInfo>,
    #[serde(rename = "forwardSecrecy")]
    pub forward_secrecy: ForwardSecrecyInfo,
    #[serde(rename = "weakCiphers")]
    pub weak_ciphers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa: Option<CaaAnalysis>,
    #[serde(rename = "analyzedAt")]
    pub analyzed_at: DateTime<Utc>,
}

/// TLS protocol version support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSupport {
    #[serde(rename = "tls13")]
    pub tls_1_3: bool,
    #[serde(rename = "tls12")]
    pub tls_1_2: bool,
    #[serde(rename = "tls11")]
    pub tls_1_1: bool,
    #[serde(rename = "tls10")]
    pub tls_1_0: bool,
}

/// Certificate information from SSL connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertificateInfo {
    pub subject: String,
    pub issuer: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "validUntil")]
    pub valid_until: String,
    #[serde(rename = "daysRemaining")]
    pub days_remaining: i64,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "signatureAlgorithm")]
    pub signature_algorithm: String,
    #[serde(rename = "keyType")]
    pub key_type: String,
    #[serde(rename = "keySize")]
    pub key_size: i32,
    #[serde(rename = "subjectAltNames")]
    pub subject_alt_names: Vec<String>,
    #[serde(rename = "chainLength")]
    pub chain_length: usize,
    #[serde(rename = "chainValid")]
    pub chain_valid: bool,
}

/// Cipher suite information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuiteInfo {
    pub name: String,
    pub protocol: String,
    #[serde(rename = "keyExchange")]
    pub key_exchange: String,
    pub encryption: String,
    pub bits: i32,
    #[serde(rename = "isWeak")]
    pub is_weak: bool,
    #[serde(rename = "hasForwardSecrecy")]
    pub has_forward_secrecy: bool,
}

/// Security issue detected during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub severity: String, // critical, warning, info
    pub code: String,
    pub title: String,
    pub description: String,
}

/// HSTS header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsInfo {
    pub enabled: bool,
    #[serde(rename = "maxAge")]
    pub max_age: i64,
    #[serde(rename = "includeSubdomains")]
    pub include_subdomains: bool,
    pub preload: bool,
}

/// OCSP stapling information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspStaplingInfo {
    pub enabled: bool,
    #[serde(rename = "responseStatus", skip_serializing_if = "Option::is_none")]
    pub response_status: Option<String>,
}

/// Forward secrecy analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardSecrecyInfo {
    pub supported: bool,
    #[serde(rename = "allCiphersSupport")]
    pub all_ciphers_support: bool,
}

// ============================================================================
// DNS Types
// ============================================================================

/// MX record with priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecord {
    pub host: String,
    pub priority: u16,
}

/// CAA record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecord {
    pub flag: u8,
    pub tag: String,
    pub value: String,
}

/// DNS lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    pub mx: Vec<MxRecord>,
    pub txt: Vec<String>,
    pub ns: Vec<String>,
    pub caa: Vec<CaaRecord>,
    #[serde(rename = "responseTimeMs")]
    pub response_time_ms: u64,
}

// ============================================================================
// Security Headers Types
// ============================================================================

/// Individual security header analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeader {
    pub name: String,
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub status: String, // "good", "warning", "bad", "info"
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

/// HSTS parsed details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsParsed {
    #[serde(rename = "maxAge")]
    pub max_age: i64,
    #[serde(rename = "includeSubdomains")]
    pub include_subdomains: bool,
    pub preload: bool,
}

/// CSP parsed details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspParsed {
    pub directives: Vec<CspDirective>,
    #[serde(rename = "hasUnsafeInline")]
    pub has_unsafe_inline: bool,
    #[serde(rename = "hasUnsafeEval")]
    pub has_unsafe_eval: bool,
}

/// Individual CSP directive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspDirective {
    pub name: String,
    pub values: Vec<String>,
}

/// Security headers analysis response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersAnalysisResponse {
    pub url: String,
    #[serde(rename = "checkedAt")]
    pub checked_at: DateTime<Utc>,
    pub grade: String,
    pub score: i32,
    pub headers: Vec<SecurityHeader>,
    #[serde(rename = "rawHeaders")]
    pub raw_headers: Vec<RawHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsts: Option<HstsParsed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csp: Option<CspParsed>,
}

/// Raw HTTP header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawHeader {
    pub name: String,
    pub value: String,
}

// ============================================================================
// RDAP Types
// ============================================================================

/// RDAP event (registration, expiration, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapEvent {
    #[serde(rename = "eventAction")]
    pub event_action: String,
    #[serde(rename = "eventDate")]
    pub event_date: Option<String>,
}

/// RDAP entity (registrant, registrar, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapEntity {
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Human-friendly summary of RDAP data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapSummary {
    #[serde(rename = "domainName")]
    pub domain_name: String,
    pub status: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    #[serde(rename = "registrarIanaId", skip_serializing_if = "Option::is_none")]
    pub registrar_iana_id: Option<String>,
    #[serde(rename = "createdDate", skip_serializing_if = "Option::is_none")]
    pub created_date: Option<String>,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    #[serde(rename = "updatedDate", skip_serializing_if = "Option::is_none")]
    pub updated_date: Option<String>,
    pub nameservers: Vec<String>,
    #[serde(rename = "dnssecEnabled")]
    pub dnssec_enabled: bool,
}

/// Full RDAP lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapLookupResult {
    pub domain: String,
    #[serde(rename = "lookedUpAt")]
    pub looked_up_at: DateTime<Utc>,
    pub summary: RdapSummary,
    #[serde(rename = "rawResponse")]
    pub raw_response: serde_json::Value,
    #[serde(rename = "rdapServer")]
    pub rdap_server: String,
    #[serde(rename = "responseTimeMs")]
    pub response_time_ms: u64,
}

// ============================================================================
// Health Check Types
// ============================================================================

/// CNAME chain resolution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnameChain {
    pub domain: String,
    pub chain: Vec<String>,
    #[serde(rename = "finalTarget")]
    pub final_target: String,
    #[serde(rename = "isCircular")]
    pub is_circular: bool,
    pub hops: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Certificate Authority Authorization analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaAnalysis {
    #[serde(rename = "foundAt")]
    pub found_at: Option<String>,
    pub inherited: bool,
    #[serde(rename = "authorizedCas")]
    pub authorized_cas: Vec<String>,
    #[serde(rename = "wildcardCas")]
    pub wildcard_cas: Vec<String>,
    #[serde(rename = "hasIodef")]
    pub has_iodef: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iodef: Option<String>,
    #[serde(rename = "hasCritical")]
    pub has_critical: bool,
    #[serde(rename = "anyCAAllowed")]
    pub any_ca_allowed: bool,
    #[serde(rename = "rawRecords")]
    pub raw_records: Vec<CaaRecordInfo>,
}

/// Individual CAA record info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecordInfo {
    pub flag: u8,
    pub tag: String,
    pub value: String,
    #[serde(rename = "foundAt")]
    pub found_at: String,
}

/// DNS resolution summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolution {
    #[serde(rename = "ipv4")]
    pub ipv4: Vec<String>,
    #[serde(rename = "ipv6")]
    pub ipv6: Vec<String>,
    pub mx: Vec<MxRecordInfo>,
    pub txt: Vec<String>,
    pub ns: Vec<String>,
    #[serde(rename = "hasIpv4")]
    pub has_ipv4: bool,
    #[serde(rename = "hasIpv6")]
    pub has_ipv6: bool,
}

/// MX record for health check display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxRecordInfo {
    pub host: String,
    pub priority: u16,
}

/// Health check recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthRecommendation {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
}

/// Overall health score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    pub grade: String,
    pub score: u8,
    pub summary: String,
}

/// SSL Health Check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslHealthCheckResult {
    pub domain: String,
    #[serde(rename = "checkedAt")]
    pub checked_at: DateTime<Utc>,
    #[serde(rename = "healthScore")]
    pub health_score: HealthScore,
    pub caa: CaaAnalysis,
    #[serde(rename = "cnameChain")]
    pub cname_chain: CnameChain,
    pub dns: DnsResolution,
    pub recommendations: Vec<HealthRecommendation>,
    #[serde(rename = "responseTimeMs")]
    pub response_time_ms: u64,
}
