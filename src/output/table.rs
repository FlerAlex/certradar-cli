use comfy_table::{presets::UTF8_FULL, Cell, CellAlignment, Color, Table};

use crate::models::*;
use crate::output::colors::*;
use crate::output::promo::format_ssl_promo;
use colored::Colorize;

/// Format SSL analysis result as a table
pub fn format_ssl_analysis(result: &SslAnalysisResult) -> String {
    let mut output = String::new();

    // Main header
    output.push_str(&main_header(&format!(
        "SSL/TLS Analysis: {}:{}",
        result.host, result.port
    )));

    // Grade and summary
    output.push_str(&format!(
        "Grade: {}    Analyzed: {}\n\n",
        format_grade(&result.security_grade),
        result.analyzed_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Certificate info
    output.push_str(&section_header("Certificate"));
    output.push_str(&format!(
        "  Subject:     {}\n",
        result.certificate.subject
    ));
    output.push_str(&format!("  Issuer:      {}\n", result.certificate.issuer));
    output.push_str(&format!(
        "  Valid From:  {}\n",
        result.certificate.valid_from
    ));
    output.push_str(&format!(
        "  Valid Until: {}\n",
        result.certificate.valid_until
    ));
    output.push_str(&format!(
        "  Days Left:   {} {}\n",
        format_days_remaining(result.certificate.days_remaining),
        if result.certificate.days_remaining > 30 {
            format_check(true)
        } else {
            format_check(false)
        }
    ));
    output.push_str(&format!(
        "  Key Type:    {} {}-bit\n",
        result.certificate.key_type, result.certificate.key_size
    ));
    output.push_str(&format!(
        "  Chain Valid: {}\n",
        format_check(result.certificate.chain_valid)
    ));
    if !result.certificate.subject_alt_names.is_empty() {
        let sans = if result.certificate.subject_alt_names.len() > 5 {
            format!(
                "{}, ... (+{} more)",
                result.certificate.subject_alt_names[..5].join(", "),
                result.certificate.subject_alt_names.len() - 5
            )
        } else {
            result.certificate.subject_alt_names.join(", ")
        };
        output.push_str(&format!("  SANs:        {}\n", sans));
    }
    output.push('\n');

    // Protocol support
    output.push_str(&section_header("Protocol Support"));
    output.push_str(&format!(
        "  TLS 1.3:  {}\n",
        format_check(result.protocols.tls_1_3)
    ));
    output.push_str(&format!(
        "  TLS 1.2:  {}\n",
        format_check(result.protocols.tls_1_2)
    ));
    output.push_str(&format!(
        "  TLS 1.1:  {} {}\n",
        format_check(!result.protocols.tls_1_1),
        if result.protocols.tls_1_1 {
            "(deprecated)".yellow().to_string()
        } else {
            "".to_string()
        }
    ));
    output.push_str(&format!(
        "  TLS 1.0:  {} {}\n",
        format_check(!result.protocols.tls_1_0),
        if result.protocols.tls_1_0 {
            "(deprecated)".yellow().to_string()
        } else {
            "".to_string()
        }
    ));
    output.push('\n');

    // Security features
    output.push_str(&section_header("Security Features"));
    if let Some(hsts) = &result.hsts {
        let preload_badge = if let Some(preload_status) = &hsts.preload_status {
            if preload_status.is_preloaded {
                " [PRELOADED]".bright_green().to_string()
            } else if hsts.preload {
                " [PENDING]".yellow().to_string()
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };
        output.push_str(&format!(
            "  HSTS:           {} (max-age: {}){}\n",
            format_check(hsts.enabled),
            hsts.max_age,
            preload_badge
        ));
    } else {
        output.push_str(&format!("  HSTS:           {}\n", format_check(false)));
    }

    if let Some(ocsp) = &result.ocsp_stapling {
        let status_info = if ocsp.enabled {
            if let Some(cert_status) = &ocsp.cert_status {
                let status_str = match cert_status.as_str() {
                    "good" => cert_status.green().to_string(),
                    "revoked" => cert_status.bright_red().to_string(),
                    _ => cert_status.yellow().to_string(),
                };
                format!(" (status: {})", status_str)
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };
        output.push_str(&format!(
            "  OCSP Stapling:  {}{}\n",
            format_check(ocsp.enabled),
            status_info
        ));
    } else {
        output.push_str(&format!("  OCSP Stapling:  {}\n", "Unknown".dimmed()));
    }

    let fs_count = result
        .cipher_suites
        .iter()
        .filter(|c| c.has_forward_secrecy)
        .count();
    output.push_str(&format!(
        "  Forward Secrecy: {} ({}/{} ciphers)\n",
        format_check(result.forward_secrecy.supported),
        fs_count,
        result.cipher_suites.len()
    ));

    if let Some(caa) = &result.caa {
        output.push_str(&format!(
            "  CAA Records:    {}\n",
            format_check(!caa.any_ca_allowed)
        ));
    }

    // Cipher preference
    if let Some(cipher_pref) = &result.cipher_preference {
        let pref_status = if cipher_pref.server_enforces_preference {
            format_check(true)
        } else {
            format_check(false)
        };
        output.push_str(&format!(
            "  Cipher Pref:    {}\n",
            pref_status
        ));
        if let Some(preferred) = &cipher_pref.preferred_cipher {
            output.push_str(&format!(
                "  Preferred:      {}\n",
                preferred.dimmed()
            ));
        }
    }
    output.push('\n');

    // Certificate Chain
    if let Some(chain) = &result.certificate.chain {
        if chain.length > 1 {
            output.push_str(&section_header("Certificate Chain"));

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec![
                Cell::new("#"),
                Cell::new("Type"),
                Cell::new("Subject"),
                Cell::new("Issuer"),
                Cell::new("Expires"),
                Cell::new("Days"),
            ]);

            for cert in &chain.certificates {
                let type_cell = match cert.cert_type.as_str() {
                    "leaf" => Cell::new("Leaf").fg(Color::Green),
                    "intermediate" => Cell::new("Intermediate").fg(Color::Yellow),
                    "root" => Cell::new("Root").fg(Color::Blue),
                    _ => Cell::new(&cert.cert_type),
                };

                let subject = if cert.subject.len() > 25 {
                    format!("{}...", &cert.subject[..22])
                } else {
                    cert.subject.clone()
                };

                let issuer = if cert.issuer.len() > 25 {
                    format!("{}...", &cert.issuer[..22])
                } else {
                    cert.issuer.clone()
                };

                let days_cell = if cert.days_remaining < 0 {
                    Cell::new("EXPIRED").fg(Color::Red)
                } else if cert.days_remaining <= 30 {
                    Cell::new(cert.days_remaining.to_string()).fg(Color::Yellow)
                } else {
                    Cell::new(cert.days_remaining.to_string()).fg(Color::Green)
                };

                table.add_row(vec![
                    Cell::new(cert.position.to_string()),
                    type_cell,
                    Cell::new(subject),
                    Cell::new(issuer),
                    Cell::new(&cert.valid_until),
                    days_cell,
                ]);
            }

            output.push_str(&table.to_string());
            output.push_str("\n\n");
        }
    }

    // Issues
    if !result.issues.is_empty() {
        output.push_str(&section_header("Issues"));
        for issue in &result.issues {
            let icon = match issue.severity.as_str() {
                "critical" => "!!!".bright_red().bold().to_string(),
                "warning" => "!!".yellow().to_string(),
                "info" => "i".blue().to_string(),
                _ => "-".to_string(),
            };
            output.push_str(&format!(
                "  {} {} - {}\n",
                icon,
                issue.title.bold(),
                issue.description.dimmed()
            ));
        }
    }

    // Promotional message (contextual, not spammy)
    output.push_str(&format_ssl_promo(result));

    output
}

/// Format certificate search results as a table
pub fn format_search_results(result: &SearchResult, limit: Option<usize>) -> String {
    let mut output = String::new();

    output.push_str(&main_header("Certificate Transparency Search Results"));
    output.push_str(&format!(
        "Found {} certificates (Source: {})\n\n",
        result.total.to_string().bold(),
        result.source
    ));

    if result.certificates.is_empty() {
        output.push_str("  No certificates found.\n");
        return output;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("ID").set_alignment(CellAlignment::Right),
        Cell::new("Common Name"),
        Cell::new("Issuer"),
        Cell::new("Not Before"),
        Cell::new("Not After"),
    ]);

    let certs_to_show = match limit {
        Some(n) => result.certificates.iter().take(n).collect::<Vec<_>>(),
        None => result.certificates.iter().collect::<Vec<_>>(),
    };

    for cert in &certs_to_show {
        // Truncate long values
        let cn = if cert.common_name.len() > 40 {
            format!("{}...", &cert.common_name[..37])
        } else {
            cert.common_name.clone()
        };

        let issuer = if cert.issuer_name.len() > 30 {
            format!("{}...", &cert.issuer_name[..27])
        } else {
            cert.issuer_name.clone()
        };

        table.add_row(vec![
            Cell::new(cert.crtsh_id.to_string()).set_alignment(CellAlignment::Right),
            Cell::new(cn),
            Cell::new(issuer),
            Cell::new(&cert.not_before),
            Cell::new(&cert.not_after),
        ]);
    }

    output.push_str(&table.to_string());

    if let Some(n) = limit {
        if result.certificates.len() > n {
            output.push_str(&format!(
                "\n\n  Showing {} of {} certificates. Use --limit to see more.\n",
                n, result.total
            ));
        }
    }

    output
}

/// Format DNS results
pub fn format_dns_results(result: &DnsResult, domain: &str) -> String {
    let mut output = String::new();

    output.push_str(&main_header(&format!("DNS Lookup: {}", domain)));
    output.push_str(&format!("Response time: {} ms\n\n", result.response_time_ms));

    // A Records
    output.push_str(&section_header("A Records (IPv4)"));
    if result.a.is_empty() {
        output.push_str("  None\n");
    } else {
        for ip in &result.a {
            output.push_str(&format!("  {}\n", ip));
        }
    }
    output.push('\n');

    // AAAA Records
    output.push_str(&section_header("AAAA Records (IPv6)"));
    if result.aaaa.is_empty() {
        output.push_str("  None\n");
    } else {
        for ip in &result.aaaa {
            output.push_str(&format!("  {}\n", ip));
        }
    }
    output.push('\n');

    // CNAME
    if let Some(cname) = &result.cname {
        output.push_str(&section_header("CNAME Record"));
        output.push_str(&format!("  {}\n\n", cname));
    }

    // MX Records
    output.push_str(&section_header("MX Records"));
    if result.mx.is_empty() {
        output.push_str("  None\n");
    } else {
        for mx in &result.mx {
            output.push_str(&format!("  {} (priority: {})\n", mx.host, mx.priority));
        }
    }
    output.push('\n');

    // NS Records
    output.push_str(&section_header("NS Records"));
    if result.ns.is_empty() {
        output.push_str("  None\n");
    } else {
        for ns in &result.ns {
            output.push_str(&format!("  {}\n", ns));
        }
    }
    output.push('\n');

    // CAA Records
    output.push_str(&section_header("CAA Records"));
    if result.caa.is_empty() {
        output.push_str("  None (any CA can issue certificates)\n");
    } else {
        for caa in &result.caa {
            output.push_str(&format!(
                "  {} {} = {}\n",
                if caa.flag != 0 {
                    "[critical]".red().to_string()
                } else {
                    "".to_string()
                },
                caa.tag,
                caa.value
            ));
        }
    }
    output.push('\n');

    // TXT Records
    output.push_str(&section_header("TXT Records"));
    if result.txt.is_empty() {
        output.push_str("  None\n");
    } else {
        for txt in &result.txt {
            let display = if txt.len() > 80 {
                format!("{}...", &txt[..77])
            } else {
                txt.clone()
            };
            output.push_str(&format!("  \"{}\"\n", display));
        }
    }

    output
}

/// Format headers analysis
pub fn format_headers_analysis(result: &HeadersAnalysisResponse) -> String {
    let mut output = String::new();

    output.push_str(&main_header(&format!("Security Headers: {}", result.url)));
    output.push_str(&format!(
        "Grade: {} (Score: {}/100)    Checked: {}\n\n",
        format_grade(&result.grade),
        result.score,
        result.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("Header"),
        Cell::new("Status"),
        Cell::new("Description"),
    ]);

    for header in &result.headers {
        let status_cell = match header.status.as_str() {
            "good" => Cell::new("Good").fg(Color::Green),
            "warning" => Cell::new("Warning").fg(Color::Yellow),
            "bad" => Cell::new("Missing/Bad").fg(Color::Red),
            "info" => Cell::new("Info").fg(Color::Blue),
            _ => Cell::new(&header.status),
        };

        let desc = if header.description.len() > 50 {
            format!("{}...", &header.description[..47])
        } else {
            header.description.clone()
        };

        table.add_row(vec![
            Cell::new(&header.name),
            status_cell,
            Cell::new(desc),
        ]);
    }

    output.push_str(&table.to_string());

    // Recommendations
    let recommendations: Vec<_> = result
        .headers
        .iter()
        .filter(|h| h.recommendation.is_some() && (h.status == "bad" || h.status == "warning"))
        .collect();

    if !recommendations.is_empty() {
        output.push_str("\n\n");
        output.push_str(&section_header("Recommendations"));
        for header in recommendations {
            if let Some(rec) = &header.recommendation {
                output.push_str(&format!("  {} {}\n", "->".yellow(), rec));
            }
        }
    }

    output
}

/// Format RDAP results
pub fn format_rdap_results(result: &RdapLookupResult) -> String {
    let mut output = String::new();

    output.push_str(&main_header(&format!(
        "RDAP Lookup: {}",
        result.summary.domain_name
    )));
    output.push_str(&format!(
        "Server: {}    Response time: {} ms\n\n",
        result.rdap_server, result.response_time_ms
    ));

    output.push_str(&section_header("Domain Information"));
    output.push_str(&format!("  Domain:      {}\n", result.summary.domain_name));

    if let Some(registrar) = &result.summary.registrar {
        output.push_str(&format!("  Registrar:   {}\n", registrar));
    }
    if let Some(iana_id) = &result.summary.registrar_iana_id {
        output.push_str(&format!("  IANA ID:     {}\n", iana_id));
    }
    output.push('\n');

    output.push_str(&section_header("Important Dates"));
    if let Some(created) = &result.summary.created_date {
        output.push_str(&format!("  Created:     {}\n", created));
    }
    if let Some(updated) = &result.summary.updated_date {
        output.push_str(&format!("  Updated:     {}\n", updated));
    }
    if let Some(expires) = &result.summary.expiration_date {
        output.push_str(&format!("  Expires:     {}\n", expires.yellow()));
    }
    output.push('\n');

    output.push_str(&section_header("Status"));
    for status in &result.summary.status {
        let icon = if status.contains("ok") || status.contains("active") {
            format_check(true)
        } else if status.contains("hold") || status.contains("prohibited") {
            format_check(false)
        } else {
            "-".dimmed().to_string()
        };
        output.push_str(&format!("  {} {}\n", icon, status));
    }
    output.push('\n');

    output.push_str(&section_header("Nameservers"));
    if result.summary.nameservers.is_empty() {
        output.push_str("  None\n");
    } else {
        for ns in &result.summary.nameservers {
            output.push_str(&format!("  {}\n", ns));
        }
    }
    output.push('\n');

    output.push_str(&section_header("Security"));
    output.push_str(&format!(
        "  DNSSEC:      {}\n",
        format_bool(result.summary.dnssec_enabled)
    ));

    output
}

/// Format health check results
pub fn format_health_results(result: &SslHealthCheckResult) -> String {
    let mut output = String::new();

    output.push_str(&main_header(&format!("SSL Health Check: {}", result.domain)));
    output.push_str(&format!(
        "Grade: {} (Score: {}/100)    Checked: {}\n",
        format_grade(&result.health_score.grade),
        result.health_score.score,
        result.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    output.push_str(&format!("{}\n\n", result.health_score.summary.dimmed()));

    // CAA Analysis
    output.push_str(&section_header("CAA Records"));
    if result.caa.any_ca_allowed {
        output.push_str(&format!(
            "  {} No CAA records - any CA can issue certificates\n",
            "!".yellow()
        ));
    } else {
        if let Some(found_at) = &result.caa.found_at {
            output.push_str(&format!(
                "  Found at: {}{}\n",
                found_at,
                if result.caa.inherited {
                    " (inherited)"
                } else {
                    ""
                }
            ));
        }
        if !result.caa.authorized_cas.is_empty() {
            output.push_str(&format!(
                "  Authorized CAs: {}\n",
                result.caa.authorized_cas.join(", ")
            ));
        }
    }
    output.push('\n');

    // CNAME Chain
    output.push_str(&section_header("CNAME Chain"));
    if result.cname_chain.hops == 0 {
        output.push_str("  No CNAME records (direct resolution)\n");
    } else {
        output.push_str(&format!(
            "  {} -> {} ({} hops)\n",
            result.cname_chain.domain, result.cname_chain.final_target, result.cname_chain.hops
        ));
        if result.cname_chain.is_circular {
            output.push_str(&format!(
                "  {} Circular CNAME detected!\n",
                "!!!".bright_red()
            ));
        }
    }
    output.push('\n');

    // DNS Resolution
    output.push_str(&section_header("DNS Resolution"));
    output.push_str(&format!(
        "  IPv4:  {} ({})\n",
        format_check(result.dns.has_ipv4),
        if result.dns.ipv4.is_empty() {
            "none".to_string()
        } else {
            result.dns.ipv4.join(", ")
        }
    ));
    output.push_str(&format!(
        "  IPv6:  {} ({})\n",
        format_check(result.dns.has_ipv6),
        if result.dns.ipv6.is_empty() {
            "none".to_string()
        } else {
            result.dns.ipv6.join(", ")
        }
    ));
    output.push('\n');

    // Recommendations
    if !result.recommendations.is_empty() {
        output.push_str(&section_header("Recommendations"));
        for rec in &result.recommendations {
            let icon = match rec.severity.as_str() {
                "critical" => "!!!".bright_red().bold().to_string(),
                "warning" => "!!".yellow().to_string(),
                "info" => "i".blue().to_string(),
                _ => "-".to_string(),
            };
            output.push_str(&format!(
                "  {} [{}] {} - {}\n",
                icon,
                rec.category,
                rec.title.bold(),
                rec.description.dimmed()
            ));
        }
    }

    output
}
