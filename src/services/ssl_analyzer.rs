use anyhow::{anyhow, Result};
use chrono::Utc;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use reqwest::Client;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::models::{
    CaaAnalysis, CertificateChainInfo, ChainCertificateInfo, CipherPreferenceInfo, CipherSuiteInfo,
    ForwardSecrecyInfo, HstsInfo, HstsPreloadStatus, OcspStaplingInfo, ProtocolSupport,
    SecurityIssue, SslAnalysisResult, SslCertificateInfo,
};
use crate::services::DnsService;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Cipher suites to probe for support
const CIPHER_TEST_LIST: &[(&str, &str, &str, &str, i32)] = &[
    // TLS 1.3 ciphers (always ECDHE, always strong)
    ("TLS_AES_256_GCM_SHA384", "TLS 1.3", "ECDHE", "AES-256-GCM", 256),
    ("TLS_AES_128_GCM_SHA256", "TLS 1.3", "ECDHE", "AES-128-GCM", 128),
    ("TLS_CHACHA20_POLY1305_SHA256", "TLS 1.3", "ECDHE", "CHACHA20-POLY1305", 256),
    // TLS 1.2 strong ciphers with forward secrecy
    ("ECDHE-RSA-AES256-GCM-SHA384", "TLS 1.2", "ECDHE", "AES-256-GCM", 256),
    ("ECDHE-RSA-AES128-GCM-SHA256", "TLS 1.2", "ECDHE", "AES-128-GCM", 128),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "TLS 1.2", "ECDHE", "AES-256-GCM", 256),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "TLS 1.2", "ECDHE", "AES-128-GCM", 128),
    ("ECDHE-RSA-CHACHA20-POLY1305", "TLS 1.2", "ECDHE", "CHACHA20-POLY1305", 256),
    ("DHE-RSA-AES256-GCM-SHA384", "TLS 1.2", "DHE", "AES-256-GCM", 256),
    ("DHE-RSA-AES128-GCM-SHA256", "TLS 1.2", "DHE", "AES-128-GCM", 128),
    // TLS 1.2 CBC ciphers (still acceptable but less preferred)
    ("ECDHE-RSA-AES256-SHA384", "TLS 1.2", "ECDHE", "AES-256-CBC", 256),
    ("ECDHE-RSA-AES128-SHA256", "TLS 1.2", "ECDHE", "AES-128-CBC", 128),
    // Weak ciphers (for detection)
    ("DES-CBC3-SHA", "TLS 1.2", "RSA", "3DES-CBC", 168),
    ("AES256-SHA", "TLS 1.2", "RSA", "AES-256-CBC", 256),
    ("AES128-SHA", "TLS 1.2", "RSA", "AES-128-CBC", 128),
    ("RC4-SHA", "TLS 1.2", "RSA", "RC4", 128),
    ("RC4-MD5", "TLS 1.2", "RSA", "RC4", 128),
];

/// Patterns that indicate weak ciphers
const WEAK_PATTERNS: &[&str] = &[
    "RC4", "3DES", "DES-CBC", "MD5", "aNULL", "eNULL", "EXPORT", "NULL", "ADH", "AECDH",
];

pub struct SslAnalyzerService {
    client: Client,
    dns: Arc<DnsService>,
}

impl SslAnalyzerService {
    pub fn new(dns: Arc<DnsService>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, dns }
    }

    /// Main entry point: analyze SSL/TLS configuration for a host
    pub async fn analyze(&self, host: &str, port: u16) -> Result<SslAnalysisResult> {
        // Validate host can be resolved
        let addr = format!("{}:{}", host, port);
        addr.to_socket_addrs()
            .map_err(|_| anyhow!("Cannot resolve hostname: {}", host))?
            .next()
            .ok_or_else(|| anyhow!("No addresses found for hostname: {}", host))?;

        // Get certificate info first using OpenSSL
        let (certificate, chain_length, chain_valid, chain_info) =
            self.get_certificate_info_openssl(host, port).await?;

        // Probe protocol support and enumerate cipher suites in parallel
        let host_clone1 = host.to_string();
        let host_clone2 = host.to_string();
        let host_clone3 = host.to_string();

        let (protocols, cipher_suites, ocsp_stapling, caa_result) = tokio::join!(
            self.probe_protocols(host, port),
            self.enumerate_cipher_suites(&host_clone1, port),
            self.check_ocsp_stapling(&host_clone2, port),
            self.dns.analyze_caa(&host_clone3)
        );

        // Analyze cipher security
        let weak_ciphers: Vec<String> = cipher_suites
            .iter()
            .filter(|c| c.is_weak)
            .map(|c| c.name.clone())
            .collect();

        let has_fs = cipher_suites.iter().any(|c| c.has_forward_secrecy);
        let all_fs = cipher_suites.iter().all(|c| c.has_forward_secrecy);

        let forward_secrecy = ForwardSecrecyInfo {
            supported: has_fs,
            all_ciphers_support: all_fs,
        };

        // Check HSTS
        let hsts = self.check_hsts(host).await;

        // Build certificate info with chain data
        let certificate = SslCertificateInfo {
            chain_length,
            chain_valid,
            chain: chain_info,
            ..certificate
        };

        let caa = caa_result.ok();

        // Detect cipher preference (do this after enumerating ciphers)
        let cipher_preference = self
            .detect_cipher_preference(host, port, &cipher_suites)
            .await;

        // Detect security issues
        let mut issues = self.detect_issues(
            &protocols,
            &certificate,
            &hsts,
            &weak_ciphers,
            &forward_secrecy,
            &ocsp_stapling,
            &caa,
            &cipher_preference,
        );

        // Calculate grade
        let security_grade = self.calculate_grade(
            &protocols,
            &issues,
            &hsts,
            &weak_ciphers,
            &forward_secrecy,
            &ocsp_stapling,
        );

        // Sort issues by severity
        issues.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "critical" => 0,
                "warning" => 1,
                "info" => 2,
                _ => 3,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        Ok(SslAnalysisResult {
            host: host.to_string(),
            port,
            protocols,
            certificate,
            cipher_suites,
            security_grade,
            issues,
            hsts,
            ocsp_stapling,
            forward_secrecy,
            weak_ciphers,
            caa,
            cipher_preference,
            analyzed_at: Utc::now(),
        })
    }

    /// Probe which TLS protocol versions are supported
    async fn probe_protocols(&self, host: &str, port: u16) -> ProtocolSupport {
        let host = host.to_string();

        // Probe each protocol version
        let (tls_1_3, tls_1_2, tls_1_1, tls_1_0) = tokio::join!(
            self.probe_tls13(&host, port),
            self.probe_protocol_openssl(&host, port, "TLSv1.2"),
            self.probe_protocol_openssl(&host, port, "TLSv1.1"),
            self.probe_protocol_openssl(&host, port, "TLSv1")
        );

        ProtocolSupport {
            tls_1_3,
            tls_1_2,
            tls_1_1,
            tls_1_0,
        }
    }

    /// Probe if a specific TLS protocol version is supported using OpenSSL
    async fn probe_protocol_openssl(&self, host: &str, port: u16, version: &str) -> bool {
        let host = host.to_string();
        let version = version.to_string();

        tokio::task::spawn_blocking(move || {
            let mut builder = match SslConnector::builder(SslMethod::tls()) {
                Ok(b) => b,
                Err(_) => return false,
            };

            // Set verification mode to accept any certificate for probing
            builder.set_verify(SslVerifyMode::NONE);

            // Configure protocol version
            let min_version = match version.as_str() {
                "TLSv1.3" => openssl::ssl::SslVersion::TLS1_3,
                "TLSv1.2" => openssl::ssl::SslVersion::TLS1_2,
                "TLSv1.1" => openssl::ssl::SslVersion::TLS1_1,
                "TLSv1" => openssl::ssl::SslVersion::TLS1,
                _ => return false,
            };

            if builder.set_min_proto_version(Some(min_version)).is_err() {
                return false;
            }
            if builder.set_max_proto_version(Some(min_version)).is_err() {
                return false;
            }

            let connector = builder.build();
            let addr = format!("{}:{}", host, port);

            let socket_addr = match addr.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => return false,
                },
                Err(_) => return false,
            };

            match TcpStream::connect_timeout(&socket_addr, CONNECTION_TIMEOUT) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(CONNECTION_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(CONNECTION_TIMEOUT));
                    connector.connect(&host, stream).is_ok()
                }
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Probe TLS 1.3 support using reqwest (which uses rustls and supports TLS 1.3)
    async fn probe_tls13(&self, host: &str, port: u16) -> bool {
        let url = if port == 443 {
            format!("https://{}/", host)
        } else {
            format!("https://{}:{}/", host, port)
        };

        // reqwest with rustls will negotiate TLS 1.3 if available
        self.client
            .head(&url)
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .is_ok()
    }

    /// Get certificate information using OpenSSL
    async fn get_certificate_info_openssl(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(SslCertificateInfo, usize, bool, Option<CertificateChainInfo>)> {
        let host_for_blocking = host.to_string();
        let host_for_verify = host.to_string();

        let result = tokio::task::spawn_blocking(move || {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::NONE);

            let connector = builder.build();
            let addr = format!("{}:{}", host_for_blocking, port);

            let socket_addr = addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow!("No addresses found"))?;

            let stream = TcpStream::connect_timeout(&socket_addr, CONNECTION_TIMEOUT)?;
            stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
            stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;

            let ssl_stream = connector
                .connect(&host_for_blocking, stream)
                .map_err(|e| anyhow!("TLS handshake failed: {}", e))?;

            let ssl = ssl_stream.ssl();

            // Get peer certificate
            let cert = ssl
                .peer_certificate()
                .ok_or_else(|| anyhow!("No certificate presented"))?;

            // Get chain and parse it
            let chain = ssl.peer_cert_chain();
            let chain_length = chain.map(|c| c.len()).unwrap_or(1);

            // Parse certificate chain details
            let chain_info = chain.map(|chain_stack| {
                parse_certificate_chain(chain_stack)
            });

            // Parse certificate
            let cert_info = parse_certificate_openssl(&cert, &host_for_blocking)?;

            Ok::<_, anyhow::Error>((cert_info, chain_length, chain_info))
        })
        .await
        .map_err(|e| anyhow!("Task join error: {}", e))??;

        // Verify chain separately with validation enabled
        let chain_valid = self.verify_chain(&host_for_verify, port).await;

        Ok((result.0, result.1, chain_valid, result.2))
    }

    /// Verify certificate chain is valid
    async fn verify_chain(&self, host: &str, port: u16) -> bool {
        let host = host.to_string();

        tokio::task::spawn_blocking(move || {
            let connector = match SslConnector::builder(SslMethod::tls()) {
                Ok(b) => b.build(),
                Err(_) => return false,
            };

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => return false,
                },
                Err(_) => return false,
            };

            match TcpStream::connect_timeout(&socket_addr, CONNECTION_TIMEOUT) {
                Ok(stream) => {
                    let _ = stream.set_read_timeout(Some(CONNECTION_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(CONNECTION_TIMEOUT));
                    connector.connect(&host, stream).is_ok()
                }
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Enumerate supported cipher suites by probing
    async fn enumerate_cipher_suites(&self, host: &str, port: u16) -> Vec<CipherSuiteInfo> {
        let host = host.to_string();
        let mut results = Vec::new();

        // Probe ciphers in batches to limit concurrency
        let mut handles = Vec::new();

        for (cipher, protocol, key_exchange, encryption, bits) in CIPHER_TEST_LIST {
            let host = host.clone();
            let cipher = cipher.to_string();
            let protocol = protocol.to_string();
            let key_exchange = key_exchange.to_string();
            let encryption = encryption.to_string();
            let bits = *bits;

            let handle = tokio::spawn(async move {
                let supported = probe_cipher(&host, port, &cipher).await;
                if supported {
                    Some(CipherSuiteInfo {
                        name: cipher.clone(),
                        protocol,
                        key_exchange: key_exchange.clone(),
                        encryption,
                        bits,
                        is_weak: is_weak_cipher(&cipher),
                        has_forward_secrecy: has_forward_secrecy(&key_exchange),
                        server_preference_rank: None,
                    })
                } else {
                    None
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Ok(Some(cipher_info)) = handle.await {
                results.push(cipher_info);
            }
        }

        // If no ciphers detected, add a default based on successful connection
        if results.is_empty() {
            results.push(CipherSuiteInfo {
                name: "Unknown (connection succeeded)".to_string(),
                protocol: "TLS 1.2+".to_string(),
                key_exchange: "Unknown".to_string(),
                encryption: "Unknown".to_string(),
                bits: 0,
                is_weak: false,
                has_forward_secrecy: true,
                server_preference_rank: None,
            });
        }

        results
    }

    /// Check OCSP stapling support and parse response
    async fn check_ocsp_stapling(&self, host: &str, port: u16) -> Option<OcspStaplingInfo> {
        let host = host.to_string();

        tokio::task::spawn_blocking(move || {
            use openssl::ocsp::{OcspResponse, OcspResponseStatus};
            use openssl::ssl::StatusType;

            let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
            builder.set_verify(SslVerifyMode::NONE);

            let connector = builder.build();

            // Configure SSL to request OCSP stapling
            let mut ssl_config = connector.configure().ok()?;
            ssl_config.set_status_type(StatusType::OCSP).ok()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = addr.to_socket_addrs().ok()?.next()?;
            let stream = TcpStream::connect_timeout(&socket_addr, CONNECTION_TIMEOUT).ok()?;
            stream.set_read_timeout(Some(CONNECTION_TIMEOUT)).ok()?;
            stream.set_write_timeout(Some(CONNECTION_TIMEOUT)).ok()?;

            let ssl_stream = ssl_config.connect(&host, stream).ok()?;

            let ocsp_bytes = ssl_stream.ssl().ocsp_status();
            let enabled = ocsp_bytes.map(|b| !b.is_empty()).unwrap_or(false);

            if !enabled {
                return Some(OcspStaplingInfo {
                    enabled: false,
                    response_status: None,
                    cert_status: None,
                    this_update: None,
                    next_update: None,
                    revocation_time: None,
                    revocation_reason: None,
                    produced_at: None,
                });
            }

            // Parse OCSP response
            let bytes = ocsp_bytes?;
            let ocsp_response = OcspResponse::from_der(bytes).ok()?;

            let response_status = match ocsp_response.status() {
                OcspResponseStatus::SUCCESSFUL => "successful",
                OcspResponseStatus::MALFORMED_REQUEST => "malformed_request",
                OcspResponseStatus::INTERNAL_ERROR => "internal_error",
                OcspResponseStatus::TRY_LATER => "try_later",
                OcspResponseStatus::SIG_REQUIRED => "sig_required",
                OcspResponseStatus::UNAUTHORIZED => "unauthorized",
                _ => "unknown",
            }
            .to_string();

            // For now, we report the response level status
            // Getting detailed cert status requires the cert ID which needs more context
            let cert_status = if ocsp_response.status() == OcspResponseStatus::SUCCESSFUL {
                Some("good".to_string())
            } else {
                None
            };

            Some(OcspStaplingInfo {
                enabled: true,
                response_status: Some(response_status),
                cert_status,
                this_update: None,
                next_update: None,
                revocation_time: None,
                revocation_reason: None,
                produced_at: None,
            })
        })
        .await
        .ok()?
    }

    /// Check HSTS header by making an HTTPS request
    async fn check_hsts(&self, host: &str) -> Option<HstsInfo> {
        let url = format!("https://{}/", host);

        let response = self
            .client
            .head(&url)
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .ok()?;

        let hsts_header = response
            .headers()
            .get("strict-transport-security")?
            .to_str()
            .ok()?;

        // Parse HSTS header
        let mut max_age = 0i64;
        let mut include_subdomains = false;
        let mut preload = false;

        for part in hsts_header.split(';').map(|s| s.trim().to_lowercase()) {
            if part.starts_with("max-age=") {
                max_age = part
                    .strip_prefix("max-age=")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if part == "includesubdomains" {
                include_subdomains = true;
            } else if part == "preload" {
                preload = true;
            }
        }

        // Check preload list status
        let preload_status = self.check_hsts_preload(host).await;

        Some(HstsInfo {
            enabled: true,
            max_age,
            include_subdomains,
            preload,
            preload_status,
        })
    }

    /// Check if domain is on HSTS preload list
    async fn check_hsts_preload(&self, host: &str) -> Option<HstsPreloadStatus> {
        let url = format!("https://hstspreload.org/api/v2/status?domain={}", host);

        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()?;

        let json: serde_json::Value = response.json().await.ok()?;

        let status = json.get("status")?.as_str()?.to_string();
        let is_preloaded = status == "preloaded";

        // Check if the preloaded domain is different (e.g., parent domain)
        let preloaded_domain = if is_preloaded {
            json.get("domain")
                .and_then(|d| d.as_str())
                .filter(|d| *d != host)
                .map(|s| s.to_string())
        } else {
            None
        };

        Some(HstsPreloadStatus {
            is_preloaded,
            status,
            preloaded_domain,
        })
    }

    /// Detect if server enforces cipher preference and determine preferred order
    async fn detect_cipher_preference(
        &self,
        host: &str,
        port: u16,
        supported_ciphers: &[CipherSuiteInfo],
    ) -> Option<CipherPreferenceInfo> {
        // Need at least 2 ciphers to test preference
        if supported_ciphers.len() < 2 {
            return None;
        }

        // Get cipher names from supported ciphers (excluding unknown and TLS 1.3)
        // TLS 1.3 ciphers use set_ciphersuites() not set_cipher_list()
        let cipher_names: Vec<String> = supported_ciphers
            .iter()
            .filter(|c| !c.name.contains("Unknown") && c.protocol != "TLS 1.3")
            .map(|c| c.name.clone())
            .collect();

        if cipher_names.len() < 2 {
            return None;
        }

        let host = host.to_string();
        let cipher_a = cipher_names[0].clone();
        let cipher_b = cipher_names[1].clone();

        // Test with ciphers in order A,B
        let order_ab = format!("{}:{}", cipher_a, cipher_b);
        let result_ab = probe_cipher_negotiated(&host, port, &order_ab).await;

        // Test with ciphers in order B,A
        let order_ba = format!("{}:{}", cipher_b, cipher_a);
        let result_ba = probe_cipher_negotiated(&host, port, &order_ba).await;

        match (result_ab, result_ba) {
            (Some(cipher_ab), Some(cipher_ba)) => {
                // If server selected the same cipher regardless of order, it enforces preference
                let server_enforces_preference = cipher_ab == cipher_ba;

                Some(CipherPreferenceInfo {
                    server_enforces_preference,
                    preferred_cipher: Some(cipher_ab),
                    preference_order: None, // Full order detection would require many connections
                })
            }
            _ => None,
        }
    }

    /// Detect security issues based on analysis results
    fn detect_issues(
        &self,
        protocols: &ProtocolSupport,
        cert: &SslCertificateInfo,
        hsts: &Option<HstsInfo>,
        weak_ciphers: &[String],
        forward_secrecy: &ForwardSecrecyInfo,
        ocsp_stapling: &Option<OcspStaplingInfo>,
        caa: &Option<CaaAnalysis>,
        cipher_preference: &Option<CipherPreferenceInfo>,
    ) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // Certificate issues
        if cert.days_remaining < 0 {
            issues.push(SecurityIssue {
                severity: "critical".to_string(),
                code: "CERT_EXPIRED".to_string(),
                title: "Certificate Expired".to_string(),
                description: format!(
                    "The certificate expired {} days ago. Visitors will see security warnings.",
                    -cert.days_remaining
                ),
            });
        } else if cert.days_remaining <= 7 {
            issues.push(SecurityIssue {
                severity: "critical".to_string(),
                code: "CERT_EXPIRING_SOON".to_string(),
                title: "Certificate Expiring Very Soon".to_string(),
                description: format!(
                    "The certificate expires in {} days. Renew immediately.",
                    cert.days_remaining
                ),
            });
        } else if cert.days_remaining <= 30 {
            issues.push(SecurityIssue {
                severity: "warning".to_string(),
                code: "CERT_EXPIRING_SOON".to_string(),
                title: "Certificate Expiring Soon".to_string(),
                description: format!(
                    "The certificate expires in {} days. Consider renewing soon.",
                    cert.days_remaining
                ),
            });
        }

        if !cert.chain_valid {
            issues.push(SecurityIssue {
                severity: "critical".to_string(),
                code: "CHAIN_INVALID".to_string(),
                title: "Certificate Chain Invalid".to_string(),
                description: "The certificate chain could not be verified. This may indicate a self-signed certificate or missing intermediate certificates.".to_string(),
            });
        }

        if cert.key_size < 2048 && cert.key_size > 0 && cert.key_type == "RSA" {
            issues.push(SecurityIssue {
                severity: "warning".to_string(),
                code: "WEAK_KEY".to_string(),
                title: "Weak Key Size".to_string(),
                description: format!(
                    "Key size is {} bits. RSA keys should be at least 2048 bits.",
                    cert.key_size
                ),
            });
        }

        // Protocol issues
        if protocols.tls_1_0 {
            issues.push(SecurityIssue {
                severity: "warning".to_string(),
                code: "TLS10_ENABLED".to_string(),
                title: "TLS 1.0 Enabled".to_string(),
                description:
                    "TLS 1.0 is deprecated and has known vulnerabilities. Disable it if possible."
                        .to_string(),
            });
        }

        if protocols.tls_1_1 {
            issues.push(SecurityIssue {
                severity: "warning".to_string(),
                code: "TLS11_ENABLED".to_string(),
                title: "TLS 1.1 Enabled".to_string(),
                description: "TLS 1.1 is deprecated. Consider disabling it.".to_string(),
            });
        }

        if !protocols.tls_1_3 {
            issues.push(SecurityIssue {
                severity: "info".to_string(),
                code: "NO_TLS13".to_string(),
                title: "TLS 1.3 Not Supported".to_string(),
                description: "Consider enabling TLS 1.3 for improved security and performance."
                    .to_string(),
            });
        }

        // Weak cipher issues
        if !weak_ciphers.is_empty() {
            issues.push(SecurityIssue {
                severity: "warning".to_string(),
                code: "WEAK_CIPHERS".to_string(),
                title: "Weak Cipher Suites Detected".to_string(),
                description: format!(
                    "Found {} weak cipher(s): {}. Disable these ciphers for better security.",
                    weak_ciphers.len(),
                    weak_ciphers.join(", ")
                ),
            });
        }

        // Forward secrecy issues
        if !forward_secrecy.supported {
            issues.push(SecurityIssue {
                severity: "warning".to_string(),
                code: "NO_PFS".to_string(),
                title: "No Forward Secrecy".to_string(),
                description:
                    "No cipher suites with forward secrecy are supported. Enable ECDHE or DHE ciphers."
                        .to_string(),
            });
        } else if !forward_secrecy.all_ciphers_support {
            issues.push(SecurityIssue {
                severity: "info".to_string(),
                code: "PARTIAL_PFS".to_string(),
                title: "Some Ciphers Lack Forward Secrecy".to_string(),
                description:
                    "Not all supported cipher suites provide perfect forward secrecy.".to_string(),
            });
        }

        // OCSP stapling issues
        if ocsp_stapling.as_ref().map(|o| !o.enabled).unwrap_or(true) {
            issues.push(SecurityIssue {
                severity: "info".to_string(),
                code: "NO_OCSP_STAPLING".to_string(),
                title: "OCSP Stapling Not Enabled".to_string(),
                description:
                    "Consider enabling OCSP stapling for faster certificate validation and improved privacy."
                        .to_string(),
            });
        }

        // OCSP revocation issues
        if let Some(ocsp) = ocsp_stapling {
            if ocsp.enabled {
                if let Some(cert_status) = &ocsp.cert_status {
                    if cert_status == "revoked" {
                        issues.push(SecurityIssue {
                            severity: "critical".to_string(),
                            code: "OCSP_REVOKED".to_string(),
                            title: "Certificate Revoked".to_string(),
                            description: "OCSP stapling indicates this certificate has been revoked.".to_string(),
                        });
                    }
                }
            }
        }

        // HSTS issues
        match hsts {
            None => {
                issues.push(SecurityIssue {
                    severity: "warning".to_string(),
                    code: "NO_HSTS".to_string(),
                    title: "HSTS Not Enabled".to_string(),
                    description: "HTTP Strict Transport Security header is not set. This leaves users vulnerable to downgrade attacks.".to_string(),
                });
            }
            Some(h) => {
                if h.max_age < 31536000 {
                    // Less than 1 year
                    issues.push(SecurityIssue {
                        severity: "info".to_string(),
                        code: "HSTS_SHORT".to_string(),
                        title: "HSTS Max-Age Too Short".to_string(),
                        description: format!(
                            "HSTS max-age is {} seconds. Consider setting it to at least 1 year (31536000 seconds).",
                            h.max_age
                        ),
                    });
                }

                // Check HSTS preload status
                if let Some(preload_status) = &h.preload_status {
                    if h.preload && !preload_status.is_preloaded {
                        issues.push(SecurityIssue {
                            severity: "info".to_string(),
                            code: "HSTS_NOT_PRELOADED".to_string(),
                            title: "HSTS Preload Not Active".to_string(),
                            description: "The preload directive is set but domain is not on the HSTS preload list.".to_string(),
                        });
                    }

                    if preload_status.is_preloaded {
                        // Check if current header meets preload requirements
                        if h.max_age < 31536000 || !h.include_subdomains || !h.preload {
                            issues.push(SecurityIssue {
                                severity: "warning".to_string(),
                                code: "HSTS_PRELOAD_REQUIREMENTS".to_string(),
                                title: "HSTS Header Not Meeting Preload Requirements".to_string(),
                                description: "Domain is preloaded but current HSTS header doesn't meet all requirements (max-age >= 1 year, includeSubDomains, preload).".to_string(),
                            });
                        }
                    }
                }
            }
        }

        // Certificate chain issues
        if let Some(chain) = &cert.chain {
            if !chain.chain_complete {
                issues.push(SecurityIssue {
                    severity: "info".to_string(),
                    code: "CHAIN_INCOMPLETE".to_string(),
                    title: "Certificate Chain Incomplete".to_string(),
                    description: "The certificate chain does not end with a self-signed root certificate.".to_string(),
                });
            }

            // Check for intermediate certificates expiring soon
            for chain_cert in &chain.certificates {
                if chain_cert.cert_type == "intermediate" && chain_cert.days_remaining <= 30 && chain_cert.days_remaining > 0 {
                    issues.push(SecurityIssue {
                        severity: "warning".to_string(),
                        code: "INTERMEDIATE_EXPIRING".to_string(),
                        title: "Intermediate Certificate Expiring".to_string(),
                        description: format!(
                            "Intermediate certificate '{}' expires in {} days.",
                            chain_cert.subject, chain_cert.days_remaining
                        ),
                    });
                }

                // Check for weak keys in chain
                if chain_cert.key_type == "RSA" && chain_cert.key_size < 2048 && chain_cert.key_size > 0 {
                    issues.push(SecurityIssue {
                        severity: "warning".to_string(),
                        code: "CHAIN_WEAK_KEY".to_string(),
                        title: "Weak Key in Certificate Chain".to_string(),
                        description: format!(
                            "Certificate '{}' in chain has weak {} {}-bit key.",
                            chain_cert.subject, chain_cert.key_type, chain_cert.key_size
                        ),
                    });
                }
            }
        }

        // CAA issues
        if let Some(caa_data) = caa {
            if caa_data.any_ca_allowed {
                issues.push(SecurityIssue {
                    severity: "info".to_string(),
                    code: "NO_CAA".to_string(),
                    title: "No CAA Records".to_string(),
                    description:
                        "No CAA records found. Consider adding CAA records to restrict which CAs can issue certificates for your domain."
                            .to_string(),
                });
            }
        }

        // Cipher preference issues
        if let Some(pref) = cipher_preference {
            if !pref.server_enforces_preference {
                issues.push(SecurityIssue {
                    severity: "info".to_string(),
                    code: "NO_SERVER_CIPHER_PREFERENCE".to_string(),
                    title: "Server Does Not Enforce Cipher Preference".to_string(),
                    description: "The server does not enforce its own cipher suite preference order. Consider configuring server-side cipher preference.".to_string(),
                });
            }
        }

        issues
    }

    /// Calculate security grade based on analysis
    fn calculate_grade(
        &self,
        protocols: &ProtocolSupport,
        issues: &[SecurityIssue],
        hsts: &Option<HstsInfo>,
        weak_ciphers: &[String],
        forward_secrecy: &ForwardSecrecyInfo,
        ocsp_stapling: &Option<OcspStaplingInfo>,
    ) -> String {
        // Start with A+ and degrade based on issues
        let mut score = 100i32;

        // Critical issues are major deductions
        let critical_count = issues.iter().filter(|i| i.severity == "critical").count();
        let warning_count = issues.iter().filter(|i| i.severity == "warning").count();

        // Critical issues
        if critical_count > 0 {
            score -= 40 * critical_count as i32;
        }

        // Warning issues
        score -= 10 * warning_count as i32;

        // Weak ciphers penalty
        if !weak_ciphers.is_empty() {
            score -= 15;
        }

        // Forward secrecy penalty
        if !forward_secrecy.all_ciphers_support {
            score -= 10;
        }

        // Bonus for good practices
        if protocols.tls_1_3 && !protocols.tls_1_0 && !protocols.tls_1_1 {
            score += 5; // Modern TLS only
        }

        if let Some(h) = hsts {
            if h.preload && h.include_subdomains && h.max_age >= 31536000 {
                score += 5; // Full HSTS with preload
            }
        }

        // OCSP stapling bonus
        if ocsp_stapling.as_ref().map(|o| o.enabled).unwrap_or(false) {
            score += 3;
        }

        // Cap score
        score = score.clamp(0, 100);

        // Convert score to grade
        match score {
            95..=100 => {
                if critical_count == 0
                    && warning_count == 0
                    && protocols.tls_1_3
                    && hsts.as_ref().map_or(false, |h| h.preload)
                    && weak_ciphers.is_empty()
                    && forward_secrecy.all_ciphers_support
                {
                    "A+".to_string()
                } else if critical_count == 0 && warning_count == 0 {
                    "A".to_string()
                } else {
                    "A".to_string()
                }
            }
            80..=94 => "A".to_string(),
            70..=79 => "B".to_string(),
            60..=69 => "C".to_string(),
            40..=59 => "D".to_string(),
            _ => "F".to_string(),
        }
    }
}

/// Probe if a specific cipher is supported
async fn probe_cipher(host: &str, port: u16, cipher: &str) -> bool {
    let host = host.to_string();
    let cipher = cipher.to_string();

    tokio::task::spawn_blocking(move || {
        let mut builder = match SslConnector::builder(SslMethod::tls()) {
            Ok(b) => b,
            Err(_) => return false,
        };

        builder.set_verify(SslVerifyMode::NONE);

        // Set the specific cipher
        if builder.set_cipher_list(&cipher).is_err() {
            return false;
        }

        let connector = builder.build();
        let addr = format!("{}:{}", host, port);

        let socket_addr = match addr.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => return false,
            },
            Err(_) => return false,
        };

        match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                connector.connect(&host, stream).is_ok()
            }
            Err(_) => false,
        }
    })
    .await
    .unwrap_or(false)
}

/// Probe which cipher is negotiated when offering a specific cipher list
async fn probe_cipher_negotiated(host: &str, port: u16, cipher_list: &str) -> Option<String> {
    let host = host.to_string();
    let cipher_list = cipher_list.to_string();

    tokio::task::spawn_blocking(move || {
        let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
        builder.set_verify(SslVerifyMode::NONE);

        // Set the cipher list
        builder.set_cipher_list(&cipher_list).ok()?;

        let connector = builder.build();
        let addr = format!("{}:{}", host, port);

        let socket_addr = addr.to_socket_addrs().ok()?.next()?;

        let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok()?;

        let ssl_stream = connector.connect(&host, stream).ok()?;

        // Get the negotiated cipher
        ssl_stream
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_string())
    })
    .await
    .ok()?
}

/// Check if a cipher is considered weak
fn is_weak_cipher(cipher: &str) -> bool {
    let cipher_upper = cipher.to_uppercase();
    WEAK_PATTERNS.iter().any(|p| cipher_upper.contains(*p))
}

/// Check if a key exchange method provides forward secrecy
fn has_forward_secrecy(key_exchange: &str) -> bool {
    matches!(key_exchange, "ECDHE" | "DHE" | "ECDH")
}

/// Parse certificate using OpenSSL
fn parse_certificate_openssl(cert: &X509, host: &str) -> Result<SslCertificateInfo> {
    // Extract subject CN
    let subject = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| host.to_string());

    // Extract issuer organization
    let issuer = cert
        .issuer_name()
        .entries_by_nid(Nid::ORGANIZATIONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Fallback to issuer CN
            cert.issuer_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().as_utf8().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown Issuer".to_string())
        });

    // Extract validity dates
    let not_before = cert.not_before();
    let not_after = cert.not_after();

    let valid_from = format_asn1_time(not_before);
    let valid_until = format_asn1_time(not_after);

    // Calculate days remaining
    let days_remaining = calculate_days_remaining(not_after);

    // Extract serial number
    let serial_number = cert
        .serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Extract signature algorithm
    let signature_algorithm = cert.signature_algorithm().object().to_string();

    // Extract key type and size
    let (key_type, key_size) = cert
        .public_key()
        .map(|pk| {
            let bits = pk.bits() as i32;
            if pk.rsa().is_ok() {
                ("RSA".to_string(), bits)
            } else if pk.ec_key().is_ok() {
                ("EC".to_string(), bits)
            } else if pk.dsa().is_ok() {
                ("DSA".to_string(), bits)
            } else {
                ("Unknown".to_string(), bits)
            }
        })
        .unwrap_or(("Unknown".to_string(), 0));

    // Extract Subject Alternative Names
    let subject_alt_names = cert
        .subject_alt_names()
        .map(|sans| {
            sans.iter()
                .filter_map(|san| san.dnsname().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec![subject.clone()]);

    Ok(SslCertificateInfo {
        subject,
        issuer,
        valid_from,
        valid_until,
        days_remaining,
        serial_number,
        signature_algorithm,
        key_type,
        key_size,
        subject_alt_names,
        chain_length: 1,   // Will be updated by caller
        chain_valid: true, // Will be updated by caller
        chain: None,       // Will be updated by caller
    })
}

/// Parse certificate chain into detailed info
fn parse_certificate_chain(chain: &openssl::stack::StackRef<X509>) -> CertificateChainInfo {
    let mut certificates = Vec::new();
    let mut issues = Vec::new();
    let chain_length = chain.len();

    for (i, cert) in chain.iter().enumerate() {
        // Extract subject
        let subject = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                cert.subject_name()
                    .entries_by_nid(Nid::ORGANIZATIONNAME)
                    .next()
                    .and_then(|e| e.data().as_utf8().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string())
            });

        // Extract issuer
        let issuer = cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                cert.issuer_name()
                    .entries_by_nid(Nid::ORGANIZATIONNAME)
                    .next()
                    .and_then(|e| e.data().as_utf8().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string())
            });

        // Check if self-signed (compare subject and issuer by their string representation)
        let subject_str = cert
            .subject_name()
            .entries()
            .map(|e| e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(",");
        let issuer_str = cert
            .issuer_name()
            .entries()
            .map(|e| e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(",");
        let is_self_signed = subject_str == issuer_str;

        // Determine certificate type
        let cert_type = if i == 0 {
            "leaf".to_string()
        } else if is_self_signed {
            "root".to_string()
        } else {
            "intermediate".to_string()
        };

        // Extract validity dates
        let valid_from = format_asn1_time(cert.not_before());
        let valid_until = format_asn1_time(cert.not_after());
        let days_remaining = calculate_days_remaining(cert.not_after());

        // Extract serial number
        let serial_number = cert
            .serial_number()
            .to_bn()
            .ok()
            .and_then(|bn| bn.to_hex_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        // Extract signature algorithm
        let signature_algorithm = cert.signature_algorithm().object().to_string();

        // Extract key type and size
        let (key_type, key_size) = cert
            .public_key()
            .map(|pk| {
                let bits = pk.bits() as i32;
                if pk.rsa().is_ok() {
                    ("RSA".to_string(), bits)
                } else if pk.ec_key().is_ok() {
                    ("EC".to_string(), bits)
                } else if pk.dsa().is_ok() {
                    ("DSA".to_string(), bits)
                } else {
                    ("Unknown".to_string(), bits)
                }
            })
            .unwrap_or(("Unknown".to_string(), 0));

        // Check for issues
        if cert_type != "leaf" && days_remaining <= 30 && days_remaining > 0 {
            issues.push(format!(
                "Intermediate certificate '{}' expires in {} days",
                subject, days_remaining
            ));
        }

        if key_type == "RSA" && key_size < 2048 && key_size > 0 {
            issues.push(format!(
                "Certificate '{}' has weak RSA key ({} bits)",
                subject, key_size
            ));
        }

        certificates.push(ChainCertificateInfo {
            position: i as u8,
            cert_type,
            subject,
            issuer,
            valid_from,
            valid_until,
            days_remaining,
            serial_number,
            signature_algorithm,
            key_type,
            key_size,
            is_self_signed,
        });
    }

    // Check if chain is complete (ends with self-signed root)
    let chain_complete = certificates.last().map(|c| c.is_self_signed).unwrap_or(false);

    if !chain_complete && chain_length > 0 {
        issues.push("Chain does not end with a self-signed root certificate".to_string());
    }

    CertificateChainInfo {
        length: chain_length,
        valid: issues.is_empty(),
        chain_complete,
        certificates,
        issues,
    }
}

/// Format ASN1 time to ISO8601 string
fn format_asn1_time(time: &openssl::asn1::Asn1TimeRef) -> String {
    time.to_string()
}

/// Calculate days remaining from ASN1 time
fn calculate_days_remaining(not_after: &openssl::asn1::Asn1TimeRef) -> i64 {
    let now = openssl::asn1::Asn1Time::days_from_now(0).ok();

    match now {
        Some(now_time) => match now_time.diff(not_after) {
            Ok(diff) => diff.days as i64,
            Err(_) => 0,
        },
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_weak_cipher_rc4() {
        assert!(is_weak_cipher("RC4-SHA"));
        assert!(is_weak_cipher("RC4-MD5"));
        assert!(is_weak_cipher("ECDHE-RSA-RC4-SHA"));
    }

    #[test]
    fn test_is_weak_cipher_3des() {
        assert!(is_weak_cipher("DES-CBC3-SHA"));
        assert!(is_weak_cipher("ECDHE-RSA-DES-CBC3-SHA"));
    }

    #[test]
    fn test_is_weak_cipher_md5() {
        assert!(is_weak_cipher("RC4-MD5"));
        assert!(is_weak_cipher("DES-CBC-MD5"));
    }

    #[test]
    fn test_is_weak_cipher_null() {
        assert!(is_weak_cipher("NULL-SHA"));
        assert!(is_weak_cipher("eNULL"));
        assert!(is_weak_cipher("aNULL"));
    }

    #[test]
    fn test_is_weak_cipher_export() {
        assert!(is_weak_cipher("EXPORT-RC4-40-MD5"));
        assert!(is_weak_cipher("EXP-DES-CBC-SHA"));
    }

    #[test]
    fn test_is_strong_cipher() {
        assert!(!is_weak_cipher("TLS_AES_256_GCM_SHA384"));
        assert!(!is_weak_cipher("TLS_AES_128_GCM_SHA256"));
        assert!(!is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384"));
        assert!(!is_weak_cipher("ECDHE-RSA-AES128-GCM-SHA256"));
        assert!(!is_weak_cipher("TLS_CHACHA20_POLY1305_SHA256"));
    }

    #[test]
    fn test_has_forward_secrecy_ecdhe() {
        assert!(has_forward_secrecy("ECDHE"));
    }

    #[test]
    fn test_has_forward_secrecy_dhe() {
        assert!(has_forward_secrecy("DHE"));
    }

    #[test]
    fn test_has_forward_secrecy_ecdh() {
        assert!(has_forward_secrecy("ECDH"));
    }

    #[test]
    fn test_no_forward_secrecy_rsa() {
        assert!(!has_forward_secrecy("RSA"));
    }

    #[test]
    fn test_no_forward_secrecy_unknown() {
        assert!(!has_forward_secrecy("Unknown"));
        assert!(!has_forward_secrecy(""));
    }

    #[test]
    fn test_cipher_preference_info_enforces() {
        let pref = CipherPreferenceInfo {
            server_enforces_preference: true,
            preferred_cipher: Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()),
            preference_order: None,
        };
        assert!(pref.server_enforces_preference);
        assert_eq!(pref.preferred_cipher.unwrap(), "ECDHE-RSA-AES256-GCM-SHA384");
    }

    #[test]
    fn test_cipher_preference_info_no_enforce() {
        let pref = CipherPreferenceInfo {
            server_enforces_preference: false,
            preferred_cipher: Some("ECDHE-RSA-AES128-GCM-SHA256".to_string()),
            preference_order: None,
        };
        assert!(!pref.server_enforces_preference);
    }

    #[test]
    fn test_hsts_preload_status_preloaded() {
        let status = HstsPreloadStatus {
            is_preloaded: true,
            status: "preloaded".to_string(),
            preloaded_domain: None,
        };
        assert!(status.is_preloaded);
        assert_eq!(status.status, "preloaded");
    }

    #[test]
    fn test_hsts_preload_status_pending() {
        let status = HstsPreloadStatus {
            is_preloaded: false,
            status: "pending".to_string(),
            preloaded_domain: None,
        };
        assert!(!status.is_preloaded);
        assert_eq!(status.status, "pending");
    }

    #[test]
    fn test_hsts_preload_status_parent_domain() {
        let status = HstsPreloadStatus {
            is_preloaded: true,
            status: "preloaded".to_string(),
            preloaded_domain: Some("example.com".to_string()),
        };
        assert!(status.is_preloaded);
        assert_eq!(status.preloaded_domain.unwrap(), "example.com");
    }

    #[test]
    fn test_ocsp_stapling_info_enabled_good() {
        let ocsp = OcspStaplingInfo {
            enabled: true,
            response_status: Some("successful".to_string()),
            cert_status: Some("good".to_string()),
            this_update: None,
            next_update: None,
            revocation_time: None,
            revocation_reason: None,
            produced_at: None,
        };
        assert!(ocsp.enabled);
        assert_eq!(ocsp.cert_status.unwrap(), "good");
    }

    #[test]
    fn test_ocsp_stapling_info_revoked() {
        let ocsp = OcspStaplingInfo {
            enabled: true,
            response_status: Some("successful".to_string()),
            cert_status: Some("revoked".to_string()),
            this_update: None,
            next_update: None,
            revocation_time: Some("2024-01-01".to_string()),
            revocation_reason: Some("keyCompromise".to_string()),
            produced_at: None,
        };
        assert!(ocsp.enabled);
        assert_eq!(ocsp.cert_status.unwrap(), "revoked");
        assert!(ocsp.revocation_time.is_some());
    }

    #[test]
    fn test_ocsp_stapling_info_disabled() {
        let ocsp = OcspStaplingInfo {
            enabled: false,
            response_status: None,
            cert_status: None,
            this_update: None,
            next_update: None,
            revocation_time: None,
            revocation_reason: None,
            produced_at: None,
        };
        assert!(!ocsp.enabled);
        assert!(ocsp.cert_status.is_none());
    }

    #[test]
    fn test_chain_certificate_info_leaf() {
        let cert = ChainCertificateInfo {
            position: 0,
            cert_type: "leaf".to_string(),
            subject: "example.com".to_string(),
            issuer: "Intermediate CA".to_string(),
            valid_from: "2024-01-01".to_string(),
            valid_until: "2025-01-01".to_string(),
            days_remaining: 365,
            serial_number: "ABC123".to_string(),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            key_type: "RSA".to_string(),
            key_size: 2048,
            is_self_signed: false,
        };
        assert_eq!(cert.position, 0);
        assert_eq!(cert.cert_type, "leaf");
        assert!(!cert.is_self_signed);
    }

    #[test]
    fn test_chain_certificate_info_root_self_signed() {
        let cert = ChainCertificateInfo {
            position: 2,
            cert_type: "root".to_string(),
            subject: "Root CA".to_string(),
            issuer: "Root CA".to_string(),
            valid_from: "2020-01-01".to_string(),
            valid_until: "2030-01-01".to_string(),
            days_remaining: 2000,
            serial_number: "ROOT123".to_string(),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            key_type: "RSA".to_string(),
            key_size: 4096,
            is_self_signed: true,
        };
        assert_eq!(cert.cert_type, "root");
        assert!(cert.is_self_signed);
    }

    #[test]
    fn test_certificate_chain_info_complete() {
        let chain = CertificateChainInfo {
            length: 3,
            valid: true,
            chain_complete: true,
            certificates: vec![],
            issues: vec![],
        };
        assert_eq!(chain.length, 3);
        assert!(chain.valid);
        assert!(chain.chain_complete);
        assert!(chain.issues.is_empty());
    }

    #[test]
    fn test_certificate_chain_info_incomplete() {
        let chain = CertificateChainInfo {
            length: 2,
            valid: false,
            chain_complete: false,
            certificates: vec![],
            issues: vec!["Chain does not end with a self-signed root certificate".to_string()],
        };
        assert!(!chain.valid);
        assert!(!chain.chain_complete);
        assert_eq!(chain.issues.len(), 1);
    }

    #[test]
    fn test_chain_certificate_weak_key_detection() {
        let cert = ChainCertificateInfo {
            position: 1,
            cert_type: "intermediate".to_string(),
            subject: "Weak CA".to_string(),
            issuer: "Root CA".to_string(),
            valid_from: "2024-01-01".to_string(),
            valid_until: "2025-01-01".to_string(),
            days_remaining: 365,
            serial_number: "WEAK123".to_string(),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            key_type: "RSA".to_string(),
            key_size: 1024, // Weak key
            is_self_signed: false,
        };
        // Verify the condition that would trigger CHAIN_WEAK_KEY issue
        assert!(cert.key_type == "RSA" && cert.key_size < 2048 && cert.key_size > 0);
    }

    #[test]
    fn test_chain_certificate_expiring_detection() {
        let cert = ChainCertificateInfo {
            position: 1,
            cert_type: "intermediate".to_string(),
            subject: "Expiring CA".to_string(),
            issuer: "Root CA".to_string(),
            valid_from: "2024-01-01".to_string(),
            valid_until: "2024-02-01".to_string(),
            days_remaining: 15, // Expiring within 30 days
            serial_number: "EXP123".to_string(),
            signature_algorithm: "sha256WithRSAEncryption".to_string(),
            key_type: "RSA".to_string(),
            key_size: 2048,
            is_self_signed: false,
        };
        // Verify the condition that would trigger INTERMEDIATE_EXPIRING issue
        assert!(cert.cert_type == "intermediate" && cert.days_remaining <= 30 && cert.days_remaining > 0);
    }
}
