use colored::Colorize;

use crate::models::{HeadersAnalysisResponse, SearchResult, SslAnalysisResult, SslHealthCheckResult};

const SSLGUARD_URL: &str = "https://sslguard.net";

/// Format the consistent promotional message
fn format_promo() -> String {
    format!(
        "\n{} Continuous monitoring at {}\n",
        "->".blue(),
        SSLGUARD_URL.cyan()
    )
}

/// Format promotional footer for SSL analysis
pub fn format_ssl_promo(_result: &SslAnalysisResult) -> String {
    format_promo()
}

/// Format promotional footer for multi-domain reports
pub fn format_multi_domain_promo(_domain_count: usize) -> String {
    format_promo()
}

/// Format promotional footer for health check
pub fn format_health_promo(_result: &SslHealthCheckResult) -> String {
    format_promo()
}

/// Format promotional footer for headers analysis
pub fn format_headers_promo(_result: &HeadersAnalysisResponse) -> String {
    format_promo()
}

/// Format promotional footer for DNS lookup
pub fn format_dns_promo(_has_caa: bool) -> String {
    format_promo()
}

/// Format promotional footer for RDAP lookup
pub fn format_rdap_promo() -> String {
    format_promo()
}

/// Format promotional footer for certificate search
pub fn format_search_promo(_result: &SearchResult) -> String {
    format_promo()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_promo_message() {
        let msg = format_promo();
        assert!(msg.contains("Continuous monitoring"));
        assert!(msg.contains("sslguard.net"));
    }
}
