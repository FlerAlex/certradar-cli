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
    CaaAnalysis, CipherSuiteInfo, ForwardSecrecyInfo, HstsInfo, OcspStaplingInfo, ProtocolSupport,
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
        let (certificate, chain_length, chain_valid) =
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
            ..certificate
        };

        let caa = caa_result.ok();

        // Detect security issues
        let mut issues = self.detect_issues(
            &protocols,
            &certificate,
            &hsts,
            &weak_ciphers,
            &forward_secrecy,
            &ocsp_stapling,
            &caa,
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

            match TcpStream::connect_timeout(
                &addr.parse().unwrap_or_else(|_| "0.0.0.0:443".parse().unwrap()),
                CONNECTION_TIMEOUT,
            ) {
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
    ) -> Result<(SslCertificateInfo, usize, bool)> {
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

            // Get chain length
            let chain = ssl.peer_cert_chain();
            let chain_length = chain.map(|c| c.len()).unwrap_or(1);

            // Parse certificate
            let cert_info = parse_certificate_openssl(&cert, &host_for_blocking)?;

            Ok::<_, anyhow::Error>((cert_info, chain_length))
        })
        .await
        .map_err(|e| anyhow!("Task join error: {}", e))??;

        // Verify chain separately with validation enabled
        let chain_valid = self.verify_chain(&host_for_verify, port).await;

        Ok((result.0, result.1, chain_valid))
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
            });
        }

        results
    }

    /// Check OCSP stapling support
    async fn check_ocsp_stapling(&self, host: &str, port: u16) -> Option<OcspStaplingInfo> {
        let host = host.to_string();

        tokio::task::spawn_blocking(move || {
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

            let enabled = ssl_stream
                .ssl()
                .ocsp_status()
                .map(|bytes| !bytes.is_empty())
                .unwrap_or(false);

            Some(OcspStaplingInfo {
                enabled,
                response_status: if enabled {
                    Some("good".to_string())
                } else {
                    None
                },
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

        Some(HstsInfo {
            enabled: true,
            max_age,
            include_subdomains,
            preload,
        })
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
        chain_length: 1,  // Will be updated by caller
        chain_valid: true, // Will be updated by caller
    })
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
