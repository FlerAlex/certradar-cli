use anyhow::Result;
use std::time::Instant;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

use crate::models::{CaaAnalysis, CaaRecord, CaaRecordInfo, CnameChain, DnsResult, MxRecord};

pub struct DnsService {
    resolver: TokioAsyncResolver,
}

impl DnsService {
    pub fn new() -> Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts);

        Ok(Self { resolver })
    }

    /// Lookup all DNS records for a domain
    pub async fn lookup_all(&self, domain: &str) -> Result<DnsResult> {
        let start = Instant::now();

        // Run all lookups in parallel
        let (a_result, aaaa_result, mx_result, txt_result, ns_result, cname_result, caa_result) =
            tokio::join!(
                self.lookup_a(domain),
                self.lookup_aaaa(domain),
                self.lookup_mx(domain),
                self.lookup_txt(domain),
                self.lookup_ns(domain),
                self.lookup_cname(domain),
                self.lookup_caa(domain),
            );

        let response_time_ms = start.elapsed().as_millis() as u64;

        Ok(DnsResult {
            a: a_result.unwrap_or_default(),
            aaaa: aaaa_result.unwrap_or_default(),
            cname: cname_result.ok().flatten(),
            mx: mx_result.unwrap_or_default(),
            txt: txt_result.unwrap_or_default(),
            ns: ns_result.unwrap_or_default(),
            caa: caa_result.unwrap_or_default(),
            response_time_ms,
        })
    }

    async fn lookup_a(&self, domain: &str) -> Result<Vec<String>> {
        let response = self.resolver.ipv4_lookup(domain).await?;
        Ok(response.iter().map(|ip| ip.to_string()).collect())
    }

    async fn lookup_aaaa(&self, domain: &str) -> Result<Vec<String>> {
        let response = self.resolver.ipv6_lookup(domain).await?;
        Ok(response.iter().map(|ip| ip.to_string()).collect())
    }

    async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>> {
        let response = self.resolver.mx_lookup(domain).await?;
        let mut records: Vec<_> = response
            .iter()
            .map(|mx| MxRecord {
                host: mx.exchange().to_string().trim_end_matches('.').to_string(),
                priority: mx.preference(),
            })
            .collect();

        // Sort by priority
        records.sort_by_key(|r| r.priority);
        Ok(records)
    }

    async fn lookup_txt(&self, domain: &str) -> Result<Vec<String>> {
        let response = self.resolver.txt_lookup(domain).await?;
        Ok(response
            .iter()
            .map(|txt| {
                txt.iter()
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect())
    }

    async fn lookup_ns(&self, domain: &str) -> Result<Vec<String>> {
        let response = self.resolver.ns_lookup(domain).await?;
        Ok(response
            .iter()
            .map(|ns| ns.to_string().trim_end_matches('.').to_string())
            .collect())
    }

    async fn lookup_cname(&self, domain: &str) -> Result<Option<String>> {
        // CNAME lookup - try to resolve and check if it's a CNAME
        match self
            .resolver
            .lookup(domain, trust_dns_resolver::proto::rr::RecordType::CNAME)
            .await
        {
            Ok(response) => {
                let cname = response
                    .iter()
                    .filter_map(|r| r.as_cname())
                    .next()
                    .map(|c| c.to_string().trim_end_matches('.').to_string());
                Ok(cname)
            }
            Err(_) => Ok(None),
        }
    }

    pub async fn lookup_caa(&self, domain: &str) -> Result<Vec<CaaRecord>> {
        let response = self
            .resolver
            .lookup(domain, trust_dns_resolver::proto::rr::RecordType::CAA)
            .await?;

        Ok(response
            .iter()
            .filter_map(|r| r.as_caa())
            .map(|caa| CaaRecord {
                flag: if caa.issuer_critical() { 1 } else { 0 },
                tag: format!("{:?}", caa.tag()).to_lowercase(),
                value: caa.value().to_string(),
            })
            .collect())
    }

    /// Resolve the full CNAME chain for a domain (up to 10 hops)
    pub async fn resolve_cname_chain(&self, domain: &str) -> Result<CnameChain> {
        const MAX_HOPS: usize = 10;
        let mut chain: Vec<String> = Vec::new();
        let mut current = domain.to_string();
        let mut visited = std::collections::HashSet::new();
        let mut is_circular = false;

        visited.insert(current.clone());

        for _ in 0..MAX_HOPS {
            match self.lookup_cname(&current).await {
                Ok(Some(target)) => {
                    let target_clean = target.trim_end_matches('.').to_lowercase();

                    if visited.contains(&target_clean) {
                        is_circular = true;
                        chain.push(target_clean);
                        break;
                    }

                    visited.insert(target_clean.clone());
                    chain.push(target_clean.clone());
                    current = target_clean;
                }
                Ok(None) => {
                    // No more CNAMEs, we've reached the final target
                    break;
                }
                Err(_) => {
                    // DNS error, stop here
                    break;
                }
            }
        }

        let final_target = if chain.is_empty() {
            domain.to_string()
        } else {
            chain.last().unwrap().clone()
        };

        Ok(CnameChain {
            domain: domain.to_string(),
            hops: chain.len(),
            chain,
            final_target,
            is_circular,
            error: None,
        })
    }

    /// Analyze CAA records, walking up the domain hierarchy if needed
    pub async fn analyze_caa(&self, domain: &str) -> Result<CaaAnalysis> {
        let parts: Vec<&str> = domain.split('.').collect();
        let mut raw_records: Vec<CaaRecordInfo> = Vec::new();
        let mut found_at: Option<String> = None;
        let mut inherited = false;

        // Start from the full domain and walk up the hierarchy
        for i in 0..parts.len().saturating_sub(1) {
            let current_domain = parts[i..].join(".");

            if let Ok(caa_records) = self.lookup_caa(&current_domain).await {
                if !caa_records.is_empty() {
                    found_at = Some(current_domain.clone());
                    inherited = i > 0;

                    for record in caa_records {
                        raw_records.push(CaaRecordInfo {
                            flag: record.flag,
                            tag: record.tag,
                            value: record.value,
                            found_at: current_domain.clone(),
                        });
                    }
                    break;
                }
            }
        }

        // Parse the records
        let mut authorized_cas: Vec<String> = Vec::new();
        let mut wildcard_cas: Vec<String> = Vec::new();
        let mut iodef: Option<String> = None;
        let mut has_critical = false;

        for record in &raw_records {
            if record.flag != 0 {
                has_critical = true;
            }

            match record.tag.as_str() {
                "issue" => {
                    let ca = record.value.split(';').next().unwrap_or("").trim();
                    if !ca.is_empty() {
                        authorized_cas.push(ca.to_string());
                    }
                }
                "issuewild" => {
                    let ca = record.value.split(';').next().unwrap_or("").trim();
                    if !ca.is_empty() {
                        wildcard_cas.push(ca.to_string());
                    }
                }
                "iodef" => {
                    iodef = Some(record.value.clone());
                }
                _ => {}
            }
        }

        // Remove duplicates
        authorized_cas.sort();
        authorized_cas.dedup();
        wildcard_cas.sort();
        wildcard_cas.dedup();

        let any_ca_allowed = raw_records.is_empty();
        let has_iodef = iodef.is_some();

        Ok(CaaAnalysis {
            found_at,
            inherited,
            authorized_cas,
            wildcard_cas,
            has_iodef,
            iodef,
            has_critical,
            any_ca_allowed,
            raw_records,
        })
    }
}
