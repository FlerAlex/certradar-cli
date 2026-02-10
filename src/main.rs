use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::control;
use std::time::Duration;

mod commands;
mod models;
mod output;
mod services;

#[derive(Parser)]
#[command(name = "certradar")]
#[command(author = "CertRadar")]
#[command(version = "0.1.1")]
#[command(about = "Certificate transparency and SSL/TLS security analysis tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: table (default) or json
    #[arg(short, long, default_value = "table", global = true)]
    output: String,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Request timeout in seconds
    #[arg(long, default_value = "30", global = true)]
    timeout: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Search Certificate Transparency logs for certificates
    Search {
        /// Domain to search for
        domain: String,

        /// Include subdomains in search
        #[arg(short, long)]
        subdomains: bool,

        /// Deduplicate results (pre-certificates)
        #[arg(short, long, default_value = "true")]
        deduplicate: bool,

        /// Maximum number of results to display
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Analyze SSL/TLS configuration for a host
    Ssl {
        /// Hostname to analyze
        host: String,

        /// Port number
        #[arg(short, long, default_value = "443")]
        port: u16,
    },

    /// Check security headers for a URL
    Headers {
        /// URL to check (https:// prefix optional)
        url: String,
    },

    /// DNS lookup for a domain
    Dns {
        /// Domain to lookup
        domain: String,
    },

    /// RDAP/WHOIS lookup for domain registration info
    Rdap {
        /// Domain to lookup
        domain: String,
    },

    /// SSL health check (CAA, CNAME chain, DNS)
    Health {
        /// Domain to check
        domain: String,
    },

    /// Multi-domain security report
    Report {
        /// Domains to analyze (space-separated)
        domains: Vec<String>,
    },
}

/// Set SSL_CERT_FILE so vendored OpenSSL can find the system CA trust store.
fn init_ssl_certs() {
    if std::env::var_os("SSL_CERT_FILE").is_some() {
        return;
    }

    // Try openssl-probe first (works well on Linux)
    let probe = openssl_probe::probe();
    if let Some(cert_file) = probe.cert_file {
        std::env::set_var("SSL_CERT_FILE", cert_file);
        return;
    }

    // Fallback for macOS and other systems where probe misses the cert bundle
    for path in ["/etc/ssl/cert.pem", "/usr/local/etc/openssl@3/cert.pem"] {
        if std::path::Path::new(path).exists() {
            std::env::set_var("SSL_CERT_FILE", path);
            return;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_ssl_certs();
    let cli = Cli::parse();

    // Handle color output
    if cli.no_color {
        control::set_override(false);
    }

    let json_output = cli.output == "json";
    let timeout = Duration::from_secs(cli.timeout);

    match cli.command {
        Commands::Search {
            domain,
            subdomains,
            deduplicate,
            limit,
        } => {
            commands::run_search(&domain, subdomains, deduplicate, limit, json_output, timeout)
                .await?;
        }

        Commands::Ssl { host, port } => {
            commands::run_ssl(&host, port, json_output).await?;
        }

        Commands::Headers { url } => {
            commands::run_headers(&url, json_output, timeout).await?;
        }

        Commands::Dns { domain } => {
            commands::run_dns(&domain, json_output).await?;
        }

        Commands::Rdap { domain } => {
            commands::run_rdap(&domain, json_output, timeout).await?;
        }

        Commands::Health { domain } => {
            commands::run_health(&domain, json_output).await?;
        }

        Commands::Report { domains } => {
            if domains.is_empty() {
                anyhow::bail!("At least one domain is required for the report command");
            }
            commands::run_report(&domains, json_output, timeout).await?;
        }
    }

    Ok(())
}
