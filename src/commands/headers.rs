use anyhow::Result;
use std::time::Duration;

use crate::output::format_headers_analysis;
use crate::services::HeadersService;

pub async fn run_headers(url: &str, json_output: bool, timeout: Duration) -> Result<()> {
    let service = HeadersService::new(timeout);
    let result = service.analyze(url).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", format_headers_analysis(&result));
    }

    Ok(())
}
