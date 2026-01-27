use anyhow::Result;

use crate::output::{format_dns_promo, format_dns_results};
use crate::services::DnsService;

pub async fn run_dns(domain: &str, json_output: bool) -> Result<()> {
    let dns = DnsService::new()?;
    let result = dns.lookup_all(domain).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", format_dns_results(&result, domain));
        print!("{}", format_dns_promo(!result.caa.is_empty()));
    }

    Ok(())
}
