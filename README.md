# CertRadar CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/certradar-cli.svg)](https://crates.io/crates/certradar-cli)
[![Downloads](https://img.shields.io/crates/d/certradar-cli.svg)](https://crates.io/crates/certradar-cli)

A command-line tool for certificate transparency search and SSL/TLS security analysis.

## Why CertRadar CLI?

Built by the team behind [CertRadar.net](https://certradar.net) and [SSLGuard.net](https://sslguard.net) - used in production to monitor thousands of certificates.

## Features

- **Certificate Transparency Search** - Find certificates issued for any domain via crt.sh
- **SSL/TLS Analysis** - Comprehensive SSL/TLS configuration analysis with security grading:
  - Protocol support detection (TLS 1.0 - 1.3)
  - Cipher suite enumeration and weakness detection
  - Certificate chain analysis with detailed info for each certificate
  - OCSP stapling status with response parsing
  - HSTS header analysis with preload list verification
  - Server cipher preference detection
  - CAA record analysis
- **Security Headers Check** - Evaluate HTTP security headers (HSTS, CSP, etc.)
- **DNS Lookup** - Query DNS records (A, AAAA, MX, TXT, NS, CAA)
- **RDAP/WHOIS Lookup** - Get domain registration information
- **SSL Health Check** - Combined check for CAA, CNAME chains, and DNS
- **Multi-domain Reports** - Security report across multiple domains

## Installation

### From Crates.io (Recommended)

```bash
cargo install certradar-cli
```

### From Source

```bash
git clone https://github.com/FlerAlex/certradar-cli.git
cd certradar-cli
cargo install --path .
```

## Usage

```
certradar-cli <COMMAND> [OPTIONS]

COMMANDS:
  search   Search Certificate Transparency logs
  ssl      Analyze SSL/TLS configuration
  headers  Check security headers
  dns      DNS lookup
  rdap     RDAP/WHOIS lookup
  health   SSL health check (CAA, CNAME, DNS)
  report   Multi-domain security report

OPTIONS:
  -o, --output <FORMAT>    Output format: table (default) or json
      --no-color           Disable colored output
      --timeout <SECS>     Request timeout in seconds [default: 30]
  -h, --help               Print help
  -V, --version            Print version
```

## Examples

### Search Certificate Transparency Logs

```bash
# Search for certificates for a domain
certradar-cli search example.com

# Include subdomains
certradar-cli search example.com --subdomains

# Limit results
certradar-cli search example.com --limit 10

# JSON output
certradar-cli search example.com -o json
```

### SSL/TLS Analysis

```bash
# Analyze a host
certradar-cli ssl example.com

# Specify port
certradar-cli ssl example.com --port 8443

# JSON output for scripting
certradar-cli ssl example.com -o json | jq .securityGrade
```

The SSL analysis includes:
- **Certificate details** - Subject, issuer, validity, key type/size, SANs
- **Certificate chain** - Full chain analysis with each certificate's details
- **Protocol support** - TLS 1.0, 1.1, 1.2, 1.3 detection
- **Cipher suites** - Enumeration with weakness detection
- **OCSP stapling** - Status and certificate revocation status
- **HSTS** - Header parsing with preload list verification (via hstspreload.org)
- **Cipher preference** - Server cipher preference enforcement detection
- **Security grade** - A+ to F grade based on configuration

### Security Headers

```bash
# Check security headers for a URL
certradar-cli headers https://example.com

# HTTPS prefix is optional
certradar-cli headers example.com
```

### DNS Lookup

```bash
# Full DNS lookup
certradar-cli dns example.com

# JSON output
certradar-cli dns example.com -o json
```

### RDAP/WHOIS Lookup

```bash
# Get domain registration info
certradar-cli rdap example.com
```

### SSL Health Check

```bash
# Check CAA records, CNAME chains, and DNS
certradar-cli health example.com
```

### Multi-Domain Report

```bash
# Generate security report for multiple domains
certradar-cli report example.com github.com google.com
```

## Output Formats

### Table (Default)

Human-readable formatted output with colors and tables.

### JSON

Machine-readable JSON output for scripting and automation.

```bash
# Pipe to jq for processing
certradar-cli ssl example.com -o json | jq '.securityGrade'

# Save to file
certradar-cli ssl example.com -o json > report.json
```

## Exit Codes

- `0` - Success
- `1` - Error (connection failed, domain not found, etc.)

## Requirements

- OpenSSL development libraries (for SSL analysis)
- Internet connection

## Need Continuous Monitoring?

This CLI is great for ad-hoc checks. For automated monitoring with alerts:

- **[SSLGuard.net](https://sslguard.net)** - Certificate expiry monitoring & alerts
- **[CertRadar.net](https://certradar.net)** - Full SSL/TLS security dashboard

## License

MIT
