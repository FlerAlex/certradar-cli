use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use crate::models::{Certificate, CertificateDetail};

static CN_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"CN=([^,]+)").unwrap());
static O_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"O=([^,]+)").unwrap());

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

    pub async fn get_certificate_detail(&self, id: i64) -> Result<Option<CertificateDetail>> {
        let url = format!("https://crt.sh/?id={}&output=json", id);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .context("Failed to fetch certificate")?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let text = response.text().await.context("Failed to read response")?;

        if text.trim() == "null" || text.trim().is_empty() {
            return Ok(None);
        }

        // crt.sh returns an array even for single cert
        let certs: Vec<CrtshCert> =
            serde_json::from_str(&text).context("Failed to parse certificate")?;

        let cert = match certs.into_iter().next() {
            Some(c) => c,
            None => return Ok(None),
        };

        // Parse SANs from name_value (newline-separated)
        let subject_alt_names: Vec<String> = cert
            .name_value
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Extract CN and O from issuer_name
        let issuer_cn = extract_cn(&cert.issuer_name);
        let issuer_o = extract_o(&cert.issuer_name);

        Ok(Some(CertificateDetail {
            crtsh_id: cert.id,
            common_name: cert.common_name,
            name_value: cert.name_value,
            issuer_name: cert.issuer_name,
            not_before: cert.not_before,
            not_after: cert.not_after,
            serial_number: cert.serial_number,
            signature_algo: None,
            key_type: None,
            key_size: None,
            subject_alt_names,
            issuer_cn,
            issuer_o,
        }))
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

fn extract_cn(issuer_name: &str) -> Option<String> {
    CN_REGEX
        .captures(issuer_name)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn extract_o(issuer_name: &str) -> Option<String> {
    O_REGEX
        .captures(issuer_name)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
}
