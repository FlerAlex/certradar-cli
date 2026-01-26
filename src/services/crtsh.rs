use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use crate::models::Certificate;

pub struct CrtshClient {
    client: Client,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct CrtshCert {
    id: i64,
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    issuer_name: String,
    #[serde(default)]
    not_before: String,
    #[serde(default)]
    not_after: String,
    #[serde(default)]
    serial_number: String,
}

impl CrtshClient {
    pub fn new(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("CertRadar-CLI/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client, timeout }
    }

    pub async fn search_certificates(
        &self,
        domain: &str,
        deduplicate: bool,
    ) -> Result<Vec<Certificate>> {
        let mut url = format!(
            "https://crt.sh/?q={}&output=json",
            urlencoding::encode(domain)
        );

        if deduplicate {
            url.push_str("&deduplicate=Y");
        }

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .context("Failed to fetch from crt.sh")?;

        if !response.status().is_success() {
            anyhow::bail!("crt.sh returned status {}", response.status());
        }

        let text = response.text().await.context("Failed to read response")?;

        // crt.sh returns "null" for no results
        if text.trim() == "null" || text.trim().is_empty() {
            return Ok(vec![]);
        }

        let certs: Vec<CrtshCert> =
            serde_json::from_str(&text).context("Failed to parse crt.sh response")?;

        Ok(certs
            .into_iter()
            .map(|c| Certificate {
                crtsh_id: c.id,
                common_name: c.common_name,
                name_value: c.name_value,
                issuer_name: c.issuer_name,
                not_before: c.not_before,
                not_after: c.not_after,
                serial_number: c.serial_number,
            })
            .collect())
    }

    pub fn filter_certificates(
        &self,
        certs: Vec<Certificate>,
        domain: &str,
        include_subdomains: bool,
    ) -> Vec<Certificate> {
        let domain_lower = domain.to_lowercase();

        certs
            .into_iter()
            .filter(|cert| self.matches_domain(cert, &domain_lower, include_subdomains))
            .collect()
    }

    fn matches_domain(&self, cert: &Certificate, domain: &str, include_subdomains: bool) -> bool {
        let cn = cert.common_name.to_lowercase();
        let name_value = cert.name_value.to_lowercase();

        if include_subdomains {
            // Match exact domain
            if cn == domain {
                return true;
            }
            // Match wildcard
            if cn == format!("*.{}", domain) {
                return true;
            }
            // Match subdomain
            if cn.ends_with(&format!(".{}", domain)) {
                return true;
            }
            // Match domain anywhere in name_value
            if name_value.contains(domain) {
                return true;
            }
        } else {
            // Exact match only
            if cn == domain {
                return true;
            }
            // Check name_value lines for exact match
            for line in name_value.lines() {
                if line.trim() == domain {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(common_name: &str, name_value: &str) -> Certificate {
        Certificate {
            crtsh_id: 1,
            common_name: common_name.to_string(),
            name_value: name_value.to_string(),
            issuer_name: "Test Issuer".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2025-01-01".to_string(),
            serial_number: "123456".to_string(),
        }
    }

    fn make_client() -> CrtshClient {
        CrtshClient::new(Duration::from_secs(30))
    }

    #[test]
    fn test_matches_domain_exact() {
        let client = make_client();
        let cert = make_cert("example.com", "example.com");

        assert!(client.matches_domain(&cert, "example.com", false));
        assert!(client.matches_domain(&cert, "example.com", true));
        assert!(!client.matches_domain(&cert, "other.com", false));
    }

    #[test]
    fn test_matches_domain_wildcard() {
        let client = make_client();
        let cert = make_cert("*.example.com", "*.example.com");

        assert!(!client.matches_domain(&cert, "example.com", false));
        assert!(client.matches_domain(&cert, "example.com", true));
    }

    #[test]
    fn test_matches_domain_subdomain() {
        let client = make_client();
        let cert = make_cert("sub.example.com", "sub.example.com");

        assert!(!client.matches_domain(&cert, "example.com", false));
        assert!(client.matches_domain(&cert, "example.com", true));
    }

    #[test]
    fn test_matches_domain_name_value() {
        let client = make_client();
        let cert = make_cert("other.com", "example.com\ntest.example.com");

        // Exact match in name_value lines (without subdomains)
        assert!(client.matches_domain(&cert, "example.com", false));

        // Contains match in name_value (with subdomains)
        assert!(client.matches_domain(&cert, "example.com", true));
    }

    #[test]
    fn test_matches_domain_case_insensitive() {
        let client = make_client();
        let cert = make_cert("EXAMPLE.COM", "EXAMPLE.COM");

        // matches_domain expects domain to be lowercase (filter_certificates handles this)
        assert!(client.matches_domain(&cert, "example.com", false));
    }

    #[test]
    fn test_filter_certificates_case_insensitive() {
        let client = make_client();
        let certs = vec![make_cert("EXAMPLE.COM", "EXAMPLE.COM")];

        // filter_certificates should handle case insensitivity
        let filtered = client.filter_certificates(certs.clone(), "example.com", false);
        assert_eq!(filtered.len(), 1);

        let filtered_upper = client.filter_certificates(certs, "EXAMPLE.COM", false);
        assert_eq!(filtered_upper.len(), 1);
    }

    #[test]
    fn test_filter_certificates() {
        let client = make_client();
        let certs = vec![
            make_cert("example.com", "example.com"),
            make_cert("sub.example.com", "sub.example.com"),
            make_cert("other.com", "other.com"),
        ];

        let filtered = client.filter_certificates(certs.clone(), "example.com", false);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].common_name, "example.com");

        let filtered_with_subs = client.filter_certificates(certs, "example.com", true);
        assert_eq!(filtered_with_subs.len(), 2);
    }
}
