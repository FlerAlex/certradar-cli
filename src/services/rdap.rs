use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::models::{RdapEntity, RdapEvent, RdapLookupResult, RdapSummary};

const IANA_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// IANA RDAP Bootstrap file structure
#[derive(Debug, Deserialize)]
struct RdapBootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

/// Cached bootstrap data
struct CachedBootstrap {
    tld_to_server: HashMap<String, String>,
    cached_at: Instant,
}

pub struct RdapService {
    client: Client,
    bootstrap_cache: RwLock<Option<CachedBootstrap>>,
}

impl RdapService {
    pub fn new(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("CertRadar-CLI/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            bootstrap_cache: RwLock::new(None),
        }
    }

    /// Get the RDAP server URL for a given TLD
    pub async fn get_rdap_server(&self, tld: &str) -> Result<Option<String>> {
        let tld_lower = tld.to_lowercase();

        // Check cache
        {
            let cache = self.bootstrap_cache.read().unwrap();
            if let Some(cached) = cache.as_ref() {
                if cached.cached_at.elapsed() < BOOTSTRAP_CACHE_TTL {
                    return Ok(cached.tld_to_server.get(&tld_lower).cloned());
                }
            }
        }

        // Fetch and cache bootstrap data
        self.refresh_bootstrap_cache().await?;

        // Return from freshly updated cache
        let cache = self.bootstrap_cache.read().unwrap();
        Ok(cache
            .as_ref()
            .and_then(|c| c.tld_to_server.get(&tld_lower).cloned()))
    }

    /// Refresh the IANA bootstrap cache
    async fn refresh_bootstrap_cache(&self) -> Result<()> {
        let response = self
            .client
            .get(IANA_BOOTSTRAP_URL)
            .send()
            .await
            .context("Failed to fetch IANA bootstrap")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "IANA bootstrap request failed with status: {}",
                response.status()
            );
        }

        let bootstrap: RdapBootstrap = response
            .json()
            .await
            .context("Failed to parse IANA bootstrap")?;

        let mut tld_to_server = HashMap::new();

        for (tlds, servers) in bootstrap.services {
            if let Some(server) = servers.first() {
                let server_url = server.trim_end_matches('/').to_string();
                for tld in tlds {
                    tld_to_server.insert(tld.to_lowercase(), server_url.clone());
                }
            }
        }

        let mut cache = self.bootstrap_cache.write().unwrap();
        *cache = Some(CachedBootstrap {
            tld_to_server,
            cached_at: Instant::now(),
        });

        Ok(())
    }

    /// Perform RDAP lookup for a domain
    pub async fn lookup(&self, domain: &str) -> Result<RdapLookupResult> {
        let start = Instant::now();

        // Extract TLD
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid domain format");
        }

        // Try multi-level TLD first (e.g., co.uk), then single TLD
        let mut rdap_server = None;

        // Try .co.uk style
        if parts.len() >= 3 {
            let two_level_tld = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            rdap_server = self.get_rdap_server(&two_level_tld).await?;
        }

        // Fall back to single TLD
        if rdap_server.is_none() {
            let tld = parts.last().unwrap();
            rdap_server = self.get_rdap_server(tld).await?;
        }

        let server = rdap_server.ok_or_else(|| {
            anyhow::anyhow!(
                "No RDAP server found for TLD: {}",
                parts.last().unwrap_or(&"unknown")
            )
        })?;

        let url = format!("{}/domain/{}", server, domain);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await
            .context("RDAP request failed")?;

        if !response.status().is_success() {
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                anyhow::bail!("Domain not found in RDAP: {}", domain);
            }
            anyhow::bail!("RDAP server returned error: {}", status);
        }

        let raw: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse RDAP response")?;

        let response_time_ms = start.elapsed().as_millis() as u64;
        let summary = self.parse_summary(domain, &raw);

        Ok(RdapLookupResult {
            domain: domain.to_string(),
            looked_up_at: Utc::now(),
            summary,
            raw_response: raw,
            rdap_server: server,
            response_time_ms,
        })
    }

    /// Parse raw RDAP response into a human-friendly summary
    pub fn parse_summary(&self, domain: &str, raw: &serde_json::Value) -> RdapSummary {
        let domain_name = raw
            .get("ldhName")
            .and_then(|v| v.as_str())
            .unwrap_or(domain)
            .to_string();

        // Parse status
        let status: Vec<String> = raw
            .get("status")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Parse events
        let events = self.parse_events(raw);
        let created_date = events
            .iter()
            .find(|e| e.event_action == "registration")
            .and_then(|e| e.event_date.clone());
        let expiration_date = events
            .iter()
            .find(|e| e.event_action == "expiration")
            .and_then(|e| e.event_date.clone());
        let updated_date = events
            .iter()
            .find(|e| e.event_action == "last changed")
            .and_then(|e| e.event_date.clone());

        // Parse entities for registrar
        let entities = self.parse_entities(raw);
        let registrar = entities
            .iter()
            .find(|e| e.roles.contains(&"registrar".to_string()))
            .and_then(|e| e.name.clone());

        // Parse registrar IANA ID from publicIds
        let registrar_iana_id = raw
            .get("entities")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|entity| {
                    if let Some(roles) = entity.get("roles").and_then(|r| r.as_array()) {
                        let is_registrar = roles.iter().any(|r| r.as_str() == Some("registrar"));
                        if is_registrar {
                            entity
                                .get("publicIds")
                                .and_then(|ids| ids.as_array())
                                .and_then(|ids| {
                                    ids.iter().find_map(|id| {
                                        if id.get("type").and_then(|t| t.as_str())
                                            == Some("IANA Registrar ID")
                                        {
                                            id.get("identifier")
                                                .and_then(|i| i.as_str())
                                                .map(String::from)
                                        } else {
                                            None
                                        }
                                    })
                                })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
            });

        // Parse nameservers
        let nameservers: Vec<String> = raw
            .get("nameservers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|ns| {
                        ns.get("ldhName")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_lowercase())
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Check DNSSEC
        let dnssec_enabled = raw
            .get("secureDNS")
            .and_then(|v| v.get("delegationSigned"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        RdapSummary {
            domain_name,
            status,
            registrar,
            registrar_iana_id,
            created_date,
            expiration_date,
            updated_date,
            nameservers,
            dnssec_enabled,
        }
    }

    /// Parse events from RDAP response
    fn parse_events(&self, raw: &serde_json::Value) -> Vec<RdapEvent> {
        raw.get("events")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|event| {
                        let action = event.get("eventAction")?.as_str()?.to_string();
                        let date = event
                            .get("eventDate")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        Some(RdapEvent {
                            event_action: action,
                            event_date: date,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parse entities from RDAP response
    fn parse_entities(&self, raw: &serde_json::Value) -> Vec<RdapEntity> {
        raw.get("entities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|entity| {
                        let roles: Vec<String> = entity
                            .get("roles")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        let handle = entity
                            .get("handle")
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        // Try to extract name from vCard
                        let name = entity
                            .get("vcardArray")
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.get(1))
                            .and_then(|v| v.as_array())
                            .and_then(|props| {
                                props.iter().find_map(|prop| {
                                    let arr = prop.as_array()?;
                                    let prop_name = arr.first()?.as_str()?;
                                    if prop_name == "fn" {
                                        arr.get(3)?.as_str().map(String::from)
                                    } else {
                                        None
                                    }
                                })
                            });

                        Some(RdapEntity {
                            roles,
                            handle,
                            name,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for RdapService {
    fn default() -> Self {
        Self::new(Duration::from_secs(15))
    }
}
