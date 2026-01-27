use anyhow::Result;
use std::time::Duration;

use crate::output::{format_rdap_promo, format_rdap_results};
use crate::services::RdapService;

pub async fn run_rdap(domain: &str, json_output: bool, timeout: Duration) -> Result<()> {
    let service = RdapService::new(timeout);
    let result = service.lookup(domain).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", format_rdap_results(&result));
        print!("{}", format_rdap_promo());
    }

    Ok(())
}
