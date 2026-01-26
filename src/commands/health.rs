use anyhow::Result;
use chrono::Utc;
use std::time::Instant;

use crate::models::{
    DnsResolution, HealthRecommendation, HealthScore, MxRecordInfo, SslHealthCheckResult,
};
use crate::output::format_health_results;
use crate::services::DnsService;

pub async fn run_health(domain: &str, json_output: bool) -> Result<()> {
    let start = Instant::now();
    let dns = DnsService::new()?;

    // Run all checks in parallel
    let (caa_result, cname_result, dns_result) = tokio::join!(
        dns.analyze_caa(domain),
        dns.resolve_cname_chain(domain),
        dns.lookup_all(domain)
    );

    let caa = caa_result?;
    let cname_chain = cname_result?;
    let dns_data = dns_result?;

    // Build DNS resolution info
    let dns_resolution = DnsResolution {
        ipv4: dns_data.a.clone(),
        ipv6: dns_data.aaaa.clone(),
        mx: dns_data
            .mx
            .iter()
            .map(|m| MxRecordInfo {
                host: m.host.clone(),
                priority: m.priority,
            })
            .collect(),
        txt: dns_data.txt.clone(),
        ns: dns_data.ns.clone(),
        has_ipv4: !dns_data.a.is_empty(),
        has_ipv6: !dns_data.aaaa.is_empty(),
    };

    // Build recommendations
    let mut recommendations = Vec::new();
    let mut score = 100u8;

    // CAA recommendations
    if caa.any_ca_allowed {
        recommendations.push(HealthRecommendation {
            severity: "warning".to_string(),
            category: "caa".to_string(),
            title: "No CAA Records".to_string(),
            description: "Add CAA records to restrict which CAs can issue certificates for your domain.".to_string(),
        });
        score = score.saturating_sub(10);
    }

    // CNAME recommendations
    if cname_chain.is_circular {
        recommendations.push(HealthRecommendation {
            severity: "critical".to_string(),
            category: "cname".to_string(),
            title: "Circular CNAME Detected".to_string(),
            description: "Fix the circular CNAME reference in your DNS configuration.".to_string(),
        });
        score = score.saturating_sub(30);
    } else if cname_chain.hops > 3 {
        recommendations.push(HealthRecommendation {
            severity: "info".to_string(),
            category: "cname".to_string(),
            title: "Long CNAME Chain".to_string(),
            description: format!(
                "CNAME chain has {} hops. Consider reducing for better performance.",
                cname_chain.hops
            ),
        });
        score = score.saturating_sub(5);
    }

    // DNS recommendations
    if !dns_resolution.has_ipv4 && !dns_resolution.has_ipv6 {
        recommendations.push(HealthRecommendation {
            severity: "critical".to_string(),
            category: "dns".to_string(),
            title: "No IP Addresses".to_string(),
            description: "Domain has no A or AAAA records.".to_string(),
        });
        score = score.saturating_sub(40);
    } else if !dns_resolution.has_ipv6 {
        recommendations.push(HealthRecommendation {
            severity: "info".to_string(),
            category: "dns".to_string(),
            title: "No IPv6 Support".to_string(),
            description: "Consider adding AAAA records for IPv6 support.".to_string(),
        });
    }

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

    let summary = if recommendations.is_empty() {
        "All health checks passed".to_string()
    } else {
        let critical = recommendations
            .iter()
            .filter(|r| r.severity == "critical")
            .count();
        let warning = recommendations
            .iter()
            .filter(|r| r.severity == "warning")
            .count();
        format!(
            "{} critical, {} warning, {} info issues",
            critical,
            warning,
            recommendations.len() - critical - warning
        )
    };

    let result = SslHealthCheckResult {
        domain: domain.to_string(),
        checked_at: Utc::now(),
        health_score: HealthScore {
            grade,
            score,
            summary,
        },
        caa,
        cname_chain,
        dns: dns_resolution,
        recommendations,
        response_time_ms: start.elapsed().as_millis() as u64,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", format_health_results(&result));
    }

    Ok(())
}
