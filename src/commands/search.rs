use anyhow::Result;
use std::time::Duration;

use crate::models::SearchResult;
use crate::output::format_search_results;
use crate::services::CrtshClient;

pub async fn run_search(
    domain: &str,
    subdomains: bool,
    deduplicate: bool,
    limit: Option<usize>,
    json_output: bool,
    timeout: Duration,
) -> Result<()> {
    let client = CrtshClient::new(timeout);

    // Search pattern: %.domain for subdomains, exact domain otherwise
    let search_pattern = if subdomains {
        format!("%.{}", domain)
    } else {
        domain.to_string()
    };

    let certificates = client
        .search_certificates(&search_pattern, deduplicate)
        .await?;

    // Filter to exact domain matches if not including subdomains
    let filtered = if !subdomains {
        client.filter_certificates(certificates, domain, false)
    } else {
        certificates
    };

    let result = SearchResult {
        total: filtered.len(),
        certificates: filtered,
        source: "crt.sh".to_string(),
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", format_search_results(&result, limit));
    }

    Ok(())
}
