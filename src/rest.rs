//! Cosmos/Akash REST API (gRPC-Gateway) query implementations.
//!
//! These functions are a drop-in alternative to the gRPC query clients.
//! Use them when the gRPC endpoint is unavailable or returns 503/501.
//!
//! Endpoint format: `https://api.akashnet.net:443`
//!
//! URL paths are derived from the generated proto type's `PACKAGE` constant
//! rather than hardcoded strings: `PACKAGE.replace('.', '/')` → URL prefix.
//! This means URL versions stay in sync with the compiled proto types automatically.

use crate::{error::DeployError, types::*};
use prost::Name as _;

// ── HTTP client ───────────────────────────────────────────────────────────────

fn rest_client() -> Result<reqwest::Client, DeployError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| DeployError::Query(format!("REST client build: {}", e)))
}

async fn get_json(url: &str) -> Result<serde_json::Value, DeployError> {
    let resp = rest_client()?
        .get(url)
        .send()
        .await
        .map_err(|e| DeployError::Query(format!("REST GET {}: {}", url, e)))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(DeployError::Query(format!(
            "REST {} → HTTP {}",
            url, status
        )));
    }

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| DeployError::Query(format!("REST parse {}: {}", url, e)))
}

/// Try each URL candidate in order, returning the first successful JSON body.
///
/// Any failure (HTTP error, transport error, connection refused) tries the next
/// candidate — some nodes close the connection without an HTTP response for
/// unrecognised paths rather than returning 404.  The last error is returned
/// only when all candidates are exhausted.
async fn get_json_any(candidates: &[String]) -> Result<serde_json::Value, DeployError> {
    let mut last_err = DeployError::Query("no REST URL candidates provided".into());
    for url in candidates {
        match get_json(url).await {
            Ok(json) => return Ok(json),
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "REST candidate failed, trying next");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// Convert a proto package string to a URL path prefix by replacing dots with slashes.
///
/// `"akash.market.v1beta5"` → `"akash/market/v1beta5"`
///
/// Used with the generated `PACKAGE` constant on each proto type so that URL
/// versions stay in sync with the compiled types without any manual string literals.
fn pkg_path(package: &str) -> String {
    package.replace('.', "/")
}

// ── Balance ───────────────────────────────────────────────────────────────────

pub async fn query_balance(api: &str, address: &str, denom: &str) -> Result<u128, DeployError> {
    // Cosmos SDK bank module — uses cosmos.bank.v1beta1 (stable, no version churn).
    let url = format!(
        "{}/cosmos/bank/v1beta1/balances/{}/by_denom?denom={}",
        api.trim_end_matches('/'),
        address,
        denom
    );
    let json = get_json(&url).await?;
    let amount = json
        .pointer("/balance/amount")
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .parse::<u128>()
        .unwrap_or(0);
    Ok(amount)
}

// ── Certificate ───────────────────────────────────────────────────────────────

pub async fn query_certificate(
    api: &str,
    owner: &str,
) -> Result<Option<CertificateInfo>, DeployError> {
    use crate::gen::akash::cert::v1::QueryCertificatesRequest;
    // PACKAGE = "akash.cert.v1" → path prefix = "akash/cert/v1"
    let pkg = pkg_path(QueryCertificatesRequest::PACKAGE);
    let base = api.trim_end_matches('/');

    let json = get_json_any(&[
        format!("{base}/{pkg}/certificates/list?filters.owner={owner}&filters.state=valid"),
        format!("{base}/{pkg}/certificates/list?owner={owner}&state=valid"),
        format!("{base}/{pkg}/certificates/list?filters.owner={owner}"),
    ])
    .await?;

    let first = match json
        .pointer("/certificates")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        Some(c) => c,
        None => return Ok(None),
    };

    let cert_b64 = first
        .pointer("/certificate/cert")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cert_pem = b64_decode(cert_b64)?;

    let serial = first
        .pointer("/serial")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(Some(CertificateInfo {
        owner: owner.to_string(),
        cert_pem,
        serial,
    }))
}

// ── Providers list ────────────────────────────────────────────────────────────

/// Fetch the first page of active providers.  Used as a connectivity pre-flight
/// check: if this succeeds the REST endpoint is reachable and answering queries.
pub async fn query_providers(api: &str) -> Result<Vec<ProviderInfo>, DeployError> {
    use crate::gen::akash::provider::v1beta4::QueryProvidersRequest;
    // PACKAGE = "akash.provider.v1beta4" → path prefix = "akash/provider/v1beta4"
    let pkg = pkg_path(QueryProvidersRequest::PACKAGE);
    let base = api.trim_end_matches('/');

    let json = get_json_any(&[
        format!("{base}/{pkg}/providers?pagination.limit=5"),
        format!("{base}/{pkg}/providers"),
    ])
    .await?;

    let mut providers = Vec::new();
    if let Some(arr) = json.pointer("/providers").and_then(|v| v.as_array()) {
        for p in arr {
            let address = p
                .pointer("/owner")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let host_uri = p
                .pointer("/host_uri")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !address.is_empty() {
                providers.push(ProviderInfo {
                    address,
                    host_uri,
                    email: String::new(),
                    website: String::new(),
                    attributes: Vec::new(),
                    cached_at: 0,
                });
            }
        }
    }
    Ok(providers)
}

// ── Provider info ─────────────────────────────────────────────────────────────

pub async fn query_provider_info(
    api: &str,
    provider: &str,
) -> Result<Option<ProviderInfo>, DeployError> {
    use crate::gen::akash::provider::v1beta4::QueryProviderRequest;
    // PACKAGE = "akash.provider.v1beta4" → path prefix = "akash/provider/v1beta4"
    let pkg = pkg_path(QueryProviderRequest::PACKAGE);
    let base = api.trim_end_matches('/');

    // 404 means provider not registered — return None rather than error.
    let resp = rest_client()?
        .get(format!("{base}/{pkg}/providers/{provider}"))
        .send()
        .await
        .map_err(|e| DeployError::Query(format!("REST provider {}: {}", provider, e)))?;

    let status = resp.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    // Some nodes return 500 for invalid/unregistered provider addresses
    // (e.g. invalid bech32 or simply not found).  Read the body and check
    // for "not found" before treating as a hard error.
    if !status.is_success() {
        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        if body.to_lowercase().contains("not found")
            || body.to_lowercase().contains("decoding bech32 failed")
            || body.to_lowercase().contains("invalid address")
        {
            return Ok(None);
        }
        return Err(DeployError::Query(format!(
            "REST provider {} → HTTP {}: {}",
            provider, code, body
        )));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| DeployError::Query(format!("REST provider parse: {}", e)))?;

    let host_uri = json
        .pointer("/provider/host_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let email = json
        .pointer("/provider/info/email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let website = json
        .pointer("/provider/info/website")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let attributes = json
        .pointer("/provider/attributes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let k = a.get("key")?.as_str()?.to_string();
                    let v = a.get("value")?.as_str()?.to_string();
                    Some((k, v))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(Some(ProviderInfo {
        address: provider.to_string(),
        host_uri,
        email,
        website,
        attributes,
        cached_at: 0,
    }))
}

// ── Bids ──────────────────────────────────────────────────────────────────────

/// Parse a bids JSON response into `Vec<Bid>`, keeping only open bids.
///
/// If `filter_dseq` is `Some(d)`, only bids whose dseq matches `d` are returned.
/// This is a client-side safety net: some nodes ignore `filters.dseq` in the REST
/// query and return ALL bids for the owner.
///
/// Results are capped at 30 to prevent overwhelming provider selection with
/// hundreds of stale bids from previous deployments.
fn parse_bids(json: &serde_json::Value, filter_dseq: Option<u64>) -> Vec<Bid> {
    let mut bids = Vec::new();
    let arr = match json.pointer("/bids").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return bids,
    };
    for entry in arr {
        let state = entry
            .pointer("/bid/state")
            .and_then(|v| v.as_str())
            .unwrap_or("open");
        if state != "open" {
            continue;
        }

        // Client-side dseq filter — verify this bid belongs to the requested deployment.
        if let Some(expected) = filter_dseq {
            let bid_dseq = entry
                .pointer("/bid/id/dseq")
                .or_else(|| entry.pointer("/bid/bid_id/dseq"))
                .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64()))
                .unwrap_or(0);
            if bid_dseq != expected {
                continue;
            }
        }

        let provider = entry
            .pointer("/bid/id/provider")
            .or_else(|| entry.pointer("/bid/bid_id/provider"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let price_uakt = entry
            .pointer("/bid/price/amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if !provider.is_empty() {
            bids.push(Bid {
                provider,
                price_uakt,
                resources: Resources::default(),
            });
        }

        if bids.len() >= 30 {
            break;
        }
    }
    bids
}

/// Query all open bids for an owner across all deployments (no dseq filter).
/// Used as a pre-flight check to verify the bids REST endpoint is reachable.
pub async fn query_bids_for_owner(api: &str, owner: &str) -> Result<Vec<Bid>, DeployError> {
    use crate::gen::akash::market::v1beta5::BidFilters;
    let pkg = pkg_path(BidFilters::PACKAGE);
    let base = api.trim_end_matches('/');

    let json = get_json_any(&[
        format!("{base}/{pkg}/bids/list?filters.owner={owner}"),
        format!("{base}/{pkg}/bids/list?owner={owner}"),
        format!("{base}/akash/market/v1/bids/list?filters.owner={owner}"),
        format!("{base}/akash/market/v1/bids/list?owner={owner}"),
    ])
    .await?;
    Ok(parse_bids(&json, None))
}

pub async fn query_bids(api: &str, owner: &str, dseq: u64) -> Result<Vec<Bid>, DeployError> {
    use crate::gen::akash::market::v1beta5::BidFilters;
    // PACKAGE = "akash.market.v1beta5" → path prefix = "akash/market/v1beta5"
    let pkg = pkg_path(BidFilters::PACKAGE);
    let base = api.trim_end_matches('/');

    let json = get_json_any(&[
        // Standard gRPC-Gateway nested-message param mapping
        format!("{base}/{pkg}/bids/list?filters.owner={owner}&filters.dseq={dseq}"),
        // Flat param variant used by some node implementations
        format!("{base}/{pkg}/bids/list?owner={owner}&dseq={dseq}"),
        // Akash v1 API (newer nodes that emit akash.market.v1.* events)
        format!("{base}/akash/market/v1/bids/list?filters.owner={owner}&filters.dseq={dseq}"),
        format!("{base}/akash/market/v1/bids/list?owner={owner}&dseq={dseq}"),
    ])
    .await?;
    Ok(parse_bids(&json, Some(dseq)))
}

// ── Lease ─────────────────────────────────────────────────────────────────────

pub async fn query_lease(
    api: &str,
    owner: &str,
    dseq: u64,
    _gseq: u32,
    _oseq: u32,
    _bseq: u32,
    provider: &str,
) -> Result<LeaseInfo, DeployError> {
    use crate::gen::akash::market::v1beta5::BidFilters;
    // BidFilters is in the same package as LeaseFilters — reuse PACKAGE.
    // PACKAGE = "akash.market.v1beta5" → path prefix = "akash/market/v1beta5"
    let pkg = pkg_path(BidFilters::PACKAGE);
    let base = api.trim_end_matches('/');

    let json = get_json_any(&[
        format!("{base}/{pkg}/leases/list?filters.owner={owner}&filters.dseq={dseq}&filters.provider={provider}"),
        format!("{base}/{pkg}/leases/list?owner={owner}&dseq={dseq}&provider={provider}"),
    ])
    .await?;

    let lease = json
        .pointer("/leases/0/lease")
        .ok_or_else(|| DeployError::Query(format!("no lease found for dseq={}", dseq)))?;

    let state_str = lease
        .pointer("/state")
        .and_then(|v| v.as_str())
        .unwrap_or("closed");

    let state = match state_str {
        "active" => LeaseState::Active,
        "insufficient_funds" | "insufficient-funds" => LeaseState::InsufficientFunds,
        _ => LeaseState::Closed,
    };

    let price_uakt = lease
        .pointer("/price/amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    Ok(LeaseInfo { state, price_uakt })
}

// ── Escrow ────────────────────────────────────────────────────────────────────

pub async fn query_escrow(api: &str, owner: &str, dseq: u64) -> Result<EscrowInfo, DeployError> {
    use crate::gen::akash::escrow::v1::QueryAccountsRequest;
    // PACKAGE = "akash.escrow.v1" → path prefix = "akash/escrow/v1"
    let pkg = pkg_path(QueryAccountsRequest::PACKAGE);
    let base = api.trim_end_matches('/');
    // Escrow XID format: `{owner}/{dseq}`
    let xid = format!("{owner}/{dseq}");

    let json = get_json_any(&[
        format!("{base}/{pkg}/accounts?ids.xid.scope=deployment&ids.xid.xid={xid}"),
        format!("{base}/{pkg}/accounts?xid={xid}"),
    ])
    .await?;

    let first = json
        .pointer("/accounts/0")
        .unwrap_or(&serde_json::Value::Null);

    let balance_uakt = first
        .pointer("/balance/amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let deposited_uakt = first
        .pointer("/depositor_settled_balance/amount")
        .or_else(|| first.pointer("/settled_balance/amount"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    Ok(EscrowInfo {
        balance_uakt,
        deposited_uakt,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn b64_decode(s: &str) -> Result<Vec<u8>, DeployError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| DeployError::Query(format!("base64 decode: {}", e)))
}
