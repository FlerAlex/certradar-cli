use anyhow::Result;
use std::sync::Arc;

use crate::output::format_ssl_analysis;
use crate::services::{DnsService, SslAnalyzerService};

pub async fn run_ssl(host: &str, port: u16, json_output: bool) -> Result<()> {
    let dns = Arc::new(DnsService::new()?);
    let analyzer = SslAnalyzerService::new(dns);

    let result = analyzer.analyze(host, port).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", format_ssl_analysis(&result));
    }

    Ok(())
}
