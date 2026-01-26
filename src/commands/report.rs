use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::Duration;

use crate::output::{format_check, format_grade, section_header};
use crate::services::{DnsService, HeadersService, RdapService, SslAnalyzerService};

pub async fn run_report(
    domains: &[String],
    json_output: bool,
    timeout: Duration,
) -> Result<()> {
    if json_output {
        return run_report_json(domains, timeout).await;
    }

    println!(
        "\n{}\n{}",
        "Multi-Domain Security Report".bold().cyan(),
        "═".repeat(60).cyan()
    );
    println!("Analyzing {} domain(s)...\n", domains.len());

    let pb = ProgressBar::new(domains.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let dns = Arc::new(DnsService::new()?);
    let ssl_analyzer = SslAnalyzerService::new(Arc::clone(&dns));
    let headers_service = HeadersService::new(timeout);
    let rdap_service = RdapService::new(timeout);

    let mut results = Vec::new();

    for domain in domains {
        pb.set_message(domain.clone());

        let mut domain_result = DomainReport {
            domain: domain.clone(),
            ssl_grade: None,
            headers_grade: None,
            dns_ok: false,
            rdap_registrar: None,
            issues: Vec::new(),
        };

        // SSL Analysis
        match ssl_analyzer.analyze(domain, 443).await {
            Ok(ssl) => {
                domain_result.ssl_grade = Some(ssl.security_grade.clone());
                for issue in &ssl.issues {
                    if issue.severity == "critical" || issue.severity == "warning" {
                        domain_result.issues.push(format!(
                            "[SSL] {} - {}",
                            issue.title, issue.description
                        ));
                    }
                }
            }
            Err(e) => {
                domain_result.issues.push(format!("[SSL] Error: {}", e));
            }
        }

        // Headers Analysis
        match headers_service.analyze(domain).await {
            Ok(headers) => {
                domain_result.headers_grade = Some(headers.grade.clone());
                for header in &headers.headers {
                    if header.status == "bad" {
                        domain_result.issues.push(format!(
                            "[Headers] {} - {}",
                            header.name, header.description
                        ));
                    }
                }
            }
            Err(e) => {
                domain_result.issues.push(format!("[Headers] Error: {}", e));
            }
        }

        // DNS Check
        match dns.lookup_all(domain).await {
            Ok(dns_result) => {
                domain_result.dns_ok = !dns_result.a.is_empty() || !dns_result.aaaa.is_empty();
                if dns_result.caa.is_empty() {
                    domain_result
                        .issues
                        .push("[DNS] No CAA records configured".to_string());
                }
            }
            Err(e) => {
                domain_result.issues.push(format!("[DNS] Error: {}", e));
            }
        }

        // RDAP Lookup
        match rdap_service.lookup(domain).await {
            Ok(rdap) => {
                domain_result.rdap_registrar = rdap.summary.registrar;
            }
            Err(_) => {
                // RDAP errors are not critical
            }
        }

        results.push(domain_result);
        pb.inc(1);
    }

    pb.finish_with_message("Done!");
    println!("\n");

    // Summary table
    println!("{}", section_header("Summary"));
    println!(
        "{:40} {:8} {:10} {:6} {}",
        "Domain".bold(),
        "SSL".bold(),
        "Headers".bold(),
        "DNS".bold(),
        "Issues".bold()
    );
    println!("{}", "-".repeat(80));

    for result in &results {
        let ssl = result
            .ssl_grade
            .as_ref()
            .map(|g| format_grade(g))
            .unwrap_or_else(|| "N/A".dimmed().to_string());

        let headers = result
            .headers_grade
            .as_ref()
            .map(|g| format_grade(g))
            .unwrap_or_else(|| "N/A".dimmed().to_string());

        let dns = format_check(result.dns_ok);
        let issues = if result.issues.is_empty() {
            "0".green().to_string()
        } else {
            result.issues.len().to_string().yellow().to_string()
        };

        let domain_display = if result.domain.len() > 38 {
            format!("{}...", &result.domain[..35])
        } else {
            result.domain.clone()
        };

        println!(
            "{:40} {:>8} {:>10} {:>6} {}",
            domain_display, ssl, headers, dns, issues
        );
    }

    // Detailed issues
    let domains_with_issues: Vec<_> = results.iter().filter(|r| !r.issues.is_empty()).collect();

    if !domains_with_issues.is_empty() {
        println!("\n{}", section_header("Issues by Domain"));

        for result in domains_with_issues {
            println!("{}", result.domain.bold());
            for issue in &result.issues {
                println!("  {} {}", "->".yellow(), issue);
            }
            println!();
        }
    }

    Ok(())
}

async fn run_report_json(domains: &[String], timeout: Duration) -> Result<()> {
    let dns = Arc::new(DnsService::new()?);
    let ssl_analyzer = SslAnalyzerService::new(Arc::clone(&dns));
    let headers_service = HeadersService::new(timeout);

    let mut json_results = Vec::new();

    for domain in domains {
        let mut entry = serde_json::json!({
            "domain": domain,
        });

        if let Ok(ssl) = ssl_analyzer.analyze(domain, 443).await {
            entry["ssl"] = serde_json::json!({
                "grade": ssl.security_grade,
                "issues": ssl.issues.len(),
            });
        }

        if let Ok(headers) = headers_service.analyze(domain).await {
            entry["headers"] = serde_json::json!({
                "grade": headers.grade,
                "score": headers.score,
            });
        }

        if let Ok(dns_result) = dns.lookup_all(domain).await {
            entry["dns"] = serde_json::json!({
                "hasIpv4": !dns_result.a.is_empty(),
                "hasIpv6": !dns_result.aaaa.is_empty(),
                "hasCaa": !dns_result.caa.is_empty(),
            });
        }

        json_results.push(entry);
    }

    println!("{}", serde_json::to_string_pretty(&json_results)?);
    Ok(())
}

#[derive(Debug)]
struct DomainReport {
    domain: String,
    ssl_grade: Option<String>,
    headers_grade: Option<String>,
    dns_ok: bool,
    rdap_registrar: Option<String>,
    issues: Vec<String>,
}
