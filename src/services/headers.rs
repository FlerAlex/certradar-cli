use anyhow::{anyhow, Result};
use chrono::Utc;
use reqwest::Client;
use std::time::Duration;

use crate::models::{
    CspDirective, CspParsed, HeadersAnalysisResponse, HstsParsed, RawHeader, SecurityHeader,
};

pub struct HeadersService {
    client: Client,
}

impl HeadersService {
    pub fn new(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Analyze security headers for a URL
    pub async fn analyze(&self, url: &str) -> Result<HeadersAnalysisResponse> {
        // Ensure URL has scheme
        let url = if !url.starts_with("http://") && !url.starts_with("https://") {
            format!("https://{}", url)
        } else {
            url.to_string()
        };

        let response = self
            .client
            .get(&url)
            .header("User-Agent", "CertRadar-CLI/1.0")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch URL: {}", e))?;

        let final_url = response.url().to_string();
        let headers = response.headers();

        // Collect raw headers
        let raw_headers: Vec<RawHeader> = headers
            .iter()
            .map(|(name, value)| RawHeader {
                name: name.to_string(),
                value: value.to_str().unwrap_or("").to_string(),
            })
            .collect();

        // Analyze each security header
        let mut security_headers = Vec::new();
        let mut score = 0i32;

        // Strict-Transport-Security
        let (hsts_header, hsts_parsed) =
            self.analyze_hsts(headers.get("strict-transport-security"));
        if hsts_header.status == "good" {
            score += 20;
        } else if hsts_header.status == "warning" {
            score += 10;
        }
        security_headers.push(hsts_header);

        // Content-Security-Policy
        let (csp_header, csp_parsed) = self.analyze_csp(headers.get("content-security-policy"));
        if csp_header.status == "good" {
            score += 25;
        } else if csp_header.status == "warning" {
            score += 15;
        }
        security_headers.push(csp_header);

        // X-Frame-Options
        let xfo_header = self.analyze_x_frame_options(headers.get("x-frame-options"));
        if xfo_header.status == "good" {
            score += 15;
        } else if xfo_header.status == "warning" {
            score += 8;
        }
        security_headers.push(xfo_header);

        // X-Content-Type-Options
        let xcto_header = self.analyze_x_content_type_options(headers.get("x-content-type-options"));
        if xcto_header.status == "good" {
            score += 10;
        }
        security_headers.push(xcto_header);

        // Referrer-Policy
        let rp_header = self.analyze_referrer_policy(headers.get("referrer-policy"));
        if rp_header.status == "good" {
            score += 10;
        } else if rp_header.status == "warning" {
            score += 5;
        }
        security_headers.push(rp_header);

        // Permissions-Policy
        let pp_header = self.analyze_permissions_policy(headers.get("permissions-policy"));
        if pp_header.status == "good" {
            score += 10;
        } else if pp_header.status == "warning" {
            score += 5;
        }
        security_headers.push(pp_header);

        // X-XSS-Protection (deprecated but still checked)
        let xxss_header = self.analyze_x_xss_protection(headers.get("x-xss-protection"));
        if xxss_header.status == "good" {
            score += 5;
        }
        security_headers.push(xxss_header);

        // Cross-Origin headers
        let coep_header = self.analyze_cross_origin_header(
            "Cross-Origin-Embedder-Policy",
            headers.get("cross-origin-embedder-policy"),
            &["require-corp", "credentialless"],
        );
        if coep_header.status == "good" {
            score += 5;
        }
        security_headers.push(coep_header);

        // Cap score at 100
        score = score.min(100);

        // Calculate grade
        let grade = match score {
            90..=100 => "A+",
            80..=89 => "A",
            70..=79 => "B",
            60..=69 => "C",
            40..=59 => "D",
            _ => "F",
        }
        .to_string();

        Ok(HeadersAnalysisResponse {
            url: final_url,
            checked_at: Utc::now(),
            grade,
            score,
            headers: security_headers,
            raw_headers,
            hsts: hsts_parsed,
            csp: csp_parsed,
        })
    }

    fn analyze_hsts(
        &self,
        header: Option<&reqwest::header::HeaderValue>,
    ) -> (SecurityHeader, Option<HstsParsed>) {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => {
                let mut max_age = 0i64;
                let mut include_subdomains = false;
                let mut preload = false;

                for part in value.split(';').map(|s| s.trim().to_lowercase()) {
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

                let (status, description, recommendation): (&str, String, Option<&str>) =
                    if max_age >= 31536000 && include_subdomains && preload {
                        (
                            "good",
                            "HSTS is properly configured with preload.".to_string(),
                            None,
                        )
                    } else if max_age >= 31536000 {
                        (
                            "good",
                            "HSTS is enabled with a good max-age.".to_string(),
                            Some("Consider adding includeSubdomains and preload directives."),
                        )
                    } else if max_age > 0 {
                        (
                            "warning",
                            format!("HSTS max-age is only {} seconds.", max_age),
                            Some("Set max-age to at least 31536000 (1 year)."),
                        )
                    } else {
                        (
                            "bad",
                            "HSTS header is present but max-age is 0 or invalid.".to_string(),
                            Some("Set a proper max-age value."),
                        )
                    };

                (
                    SecurityHeader {
                        name: "Strict-Transport-Security".to_string(),
                        present: true,
                        value: Some(value.to_string()),
                        status: status.to_string(),
                        description,
                        recommendation: recommendation.map(|s| s.to_string()),
                    },
                    Some(HstsParsed {
                        max_age,
                        include_subdomains,
                        preload,
                    }),
                )
            }
            None => (
                SecurityHeader {
                    name: "Strict-Transport-Security".to_string(),
                    present: false,
                    value: None,
                    status: "bad".to_string(),
                    description: "HSTS header is missing. Site is vulnerable to downgrade attacks."
                        .to_string(),
                    recommendation: Some(
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                            .to_string(),
                    ),
                },
                None,
            ),
        }
    }

    fn analyze_csp(
        &self,
        header: Option<&reqwest::header::HeaderValue>,
    ) -> (SecurityHeader, Option<CspParsed>) {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => {
                let mut directives = Vec::new();
                let mut has_unsafe_inline = false;
                let mut has_unsafe_eval = false;

                for directive in value.split(';').map(|s| s.trim()) {
                    if directive.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = directive.split_whitespace().collect();
                    if let Some((name, values)) = parts.split_first() {
                        let values: Vec<String> = values.iter().map(|s| s.to_string()).collect();

                        if values.iter().any(|v| v.contains("unsafe-inline")) {
                            has_unsafe_inline = true;
                        }
                        if values.iter().any(|v| v.contains("unsafe-eval")) {
                            has_unsafe_eval = true;
                        }

                        directives.push(CspDirective {
                            name: name.to_string(),
                            values,
                        });
                    }
                }

                let (status, description, recommendation) = if has_unsafe_inline || has_unsafe_eval
                {
                    (
                        "warning",
                        "CSP is present but contains unsafe directives.",
                        Some("Remove 'unsafe-inline' and 'unsafe-eval' if possible."),
                    )
                } else if directives.iter().any(|d| d.name == "default-src") {
                    ("good", "CSP is properly configured.", None)
                } else {
                    (
                        "warning",
                        "CSP is present but may be incomplete.",
                        Some("Add a default-src directive."),
                    )
                };

                // Truncate value for display
                let display_value = if value.len() > 200 {
                    format!("{}...", &value[..200])
                } else {
                    value.to_string()
                };

                (
                    SecurityHeader {
                        name: "Content-Security-Policy".to_string(),
                        present: true,
                        value: Some(display_value),
                        status: status.to_string(),
                        description: description.to_string(),
                        recommendation: recommendation.map(|s| s.to_string()),
                    },
                    Some(CspParsed {
                        directives,
                        has_unsafe_inline,
                        has_unsafe_eval,
                    }),
                )
            }
            None => (
                SecurityHeader {
                    name: "Content-Security-Policy".to_string(),
                    present: false,
                    value: None,
                    status: "bad".to_string(),
                    description: "CSP header is missing. Site is more vulnerable to XSS attacks."
                        .to_string(),
                    recommendation: Some(
                        "Add a Content-Security-Policy header to control resource loading."
                            .to_string(),
                    ),
                },
                None,
            ),
        }
    }

    fn analyze_x_frame_options(
        &self,
        header: Option<&reqwest::header::HeaderValue>,
    ) -> SecurityHeader {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => {
                let upper = value.to_uppercase();
                let (status, description) = if upper == "DENY" {
                    (
                        "good",
                        "Page cannot be framed. Best protection against clickjacking.",
                    )
                } else if upper == "SAMEORIGIN" {
                    ("good", "Page can only be framed by same origin.")
                } else if upper.starts_with("ALLOW-FROM") {
                    (
                        "warning",
                        "ALLOW-FROM is deprecated and not supported by modern browsers.",
                    )
                } else {
                    ("warning", "Unrecognized X-Frame-Options value.")
                };

                SecurityHeader {
                    name: "X-Frame-Options".to_string(),
                    present: true,
                    value: Some(value.to_string()),
                    status: status.to_string(),
                    description: description.to_string(),
                    recommendation: None,
                }
            }
            None => SecurityHeader {
                name: "X-Frame-Options".to_string(),
                present: false,
                value: None,
                status: "bad".to_string(),
                description: "Missing. Site may be vulnerable to clickjacking.".to_string(),
                recommendation: Some("Add: X-Frame-Options: DENY".to_string()),
            },
        }
    }

    fn analyze_x_content_type_options(
        &self,
        header: Option<&reqwest::header::HeaderValue>,
    ) -> SecurityHeader {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => {
                let status = if value.to_lowercase() == "nosniff" {
                    "good"
                } else {
                    "warning"
                };

                SecurityHeader {
                    name: "X-Content-Type-Options".to_string(),
                    present: true,
                    value: Some(value.to_string()),
                    status: status.to_string(),
                    description: "Prevents MIME type sniffing.".to_string(),
                    recommendation: None,
                }
            }
            None => SecurityHeader {
                name: "X-Content-Type-Options".to_string(),
                present: false,
                value: None,
                status: "bad".to_string(),
                description: "Missing. Browser may sniff content types.".to_string(),
                recommendation: Some("Add: X-Content-Type-Options: nosniff".to_string()),
            },
        }
    }

    fn analyze_referrer_policy(
        &self,
        header: Option<&reqwest::header::HeaderValue>,
    ) -> SecurityHeader {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => {
                let good_policies = [
                    "no-referrer",
                    "no-referrer-when-downgrade",
                    "strict-origin",
                    "strict-origin-when-cross-origin",
                ];
                let status = if good_policies.iter().any(|p| value.to_lowercase().contains(p)) {
                    "good"
                } else if value.to_lowercase() == "unsafe-url" {
                    "bad"
                } else {
                    "warning"
                };

                SecurityHeader {
                    name: "Referrer-Policy".to_string(),
                    present: true,
                    value: Some(value.to_string()),
                    status: status.to_string(),
                    description: "Controls referrer information sent with requests.".to_string(),
                    recommendation: None,
                }
            }
            None => SecurityHeader {
                name: "Referrer-Policy".to_string(),
                present: false,
                value: None,
                status: "warning".to_string(),
                description: "Missing. Browser will use default referrer behavior.".to_string(),
                recommendation: Some(
                    "Add: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
                ),
            },
        }
    }

    fn analyze_permissions_policy(
        &self,
        header: Option<&reqwest::header::HeaderValue>,
    ) -> SecurityHeader {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => SecurityHeader {
                name: "Permissions-Policy".to_string(),
                present: true,
                value: Some(if value.len() > 150 {
                    format!("{}...", &value[..150])
                } else {
                    value.to_string()
                }),
                status: "good".to_string(),
                description: "Controls browser feature permissions.".to_string(),
                recommendation: None,
            },
            None => SecurityHeader {
                name: "Permissions-Policy".to_string(),
                present: false,
                value: None,
                status: "info".to_string(),
                description: "Not set. Consider restricting browser features.".to_string(),
                recommendation: Some(
                    "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()".to_string(),
                ),
            },
        }
    }

    fn analyze_x_xss_protection(
        &self,
        header: Option<&reqwest::header::HeaderValue>,
    ) -> SecurityHeader {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => {
                let (status, description) = if value.contains("1") && value.contains("block") {
                    ("good", "XSS filter enabled with block mode.")
                } else if value.starts_with("0") {
                    (
                        "info",
                        "XSS filter disabled (recommended for sites with CSP).",
                    )
                } else {
                    ("warning", "XSS filter enabled but not in block mode.")
                };

                SecurityHeader {
                    name: "X-XSS-Protection".to_string(),
                    present: true,
                    value: Some(value.to_string()),
                    status: status.to_string(),
                    description: format!("{} Note: This header is deprecated.", description),
                    recommendation: None,
                }
            }
            None => SecurityHeader {
                name: "X-XSS-Protection".to_string(),
                present: false,
                value: None,
                status: "info".to_string(),
                description: "Not set. This header is deprecated in modern browsers.".to_string(),
                recommendation: None,
            },
        }
    }

    fn analyze_cross_origin_header(
        &self,
        name: &str,
        header: Option<&reqwest::header::HeaderValue>,
        good_values: &[&str],
    ) -> SecurityHeader {
        match header.and_then(|v| v.to_str().ok()) {
            Some(value) => {
                let status = if good_values.iter().any(|v| value.to_lowercase().contains(v)) {
                    "good"
                } else {
                    "warning"
                };

                SecurityHeader {
                    name: name.to_string(),
                    present: true,
                    value: Some(value.to_string()),
                    status: status.to_string(),
                    description: "Cross-origin isolation header.".to_string(),
                    recommendation: None,
                }
            }
            None => SecurityHeader {
                name: name.to_string(),
                present: false,
                value: None,
                status: "info".to_string(),
                description: "Not set. Required for advanced features like SharedArrayBuffer."
                    .to_string(),
                recommendation: None,
            },
        }
    }
}
