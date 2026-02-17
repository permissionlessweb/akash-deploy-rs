//! Interactive deployment example.
//!
//! Runs the full Akash deployment workflow with interactive provider selection.
//!
//! Usage:
//!   cargo run --example deploy
//!
//! Environment:
//!   TEST_MNEMONIC       - BIP39 mnemonic (required)
//!   TEST_RPC_ENDPOINT   - RPC endpoint  (default: https://rpc.akashnet.net:443)
//!   TEST_GRPC_ENDPOINT  - gRPC endpoint (default: https://grpc.akashnet.net:443)

use akash_deploy_rs::{
    AkashBackend, AkashClient, DeploymentState, DeploymentWorkflow, InputRequired, KeySigner,
    ProviderInfo, Step, StepResult, WorkflowConfig,
};
use std::io::{self, BufRead, Write};

const DEFAULT_RPC: &str = "https://rpc.akashnet.net:443";
const DEFAULT_GRPC: &str = "https://grpc.akashnet.net:443";

fn rpc() -> String {
    std::env::var("TEST_RPC_ENDPOINT").unwrap_or_else(|_| DEFAULT_RPC.to_string())
}

fn grpc() -> String {
    std::env::var("TEST_GRPC_ENDPOINT").unwrap_or_else(|_| DEFAULT_GRPC.to_string())
}

/// Query provider info for each bid and display enriched selection.
async fn interactive_select_provider(
    bids: &[akash_deploy_rs::Bid],
    client: &AkashClient,
) -> Result<String, Box<dyn std::error::Error>> {
    println!();
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("  PROVIDER SELECTION — {} bid(s) received", bids.len());
    println!("═══════════════════════════════════════════════════════════════════════");
    println!();

    // Query provider info for each bid (best-effort — display what we can)
    let mut provider_infos: Vec<Option<ProviderInfo>> = Vec::with_capacity(bids.len());
    for bid in bids {
        match client.query_provider_info(&bid.provider).await {
            Ok(info) => provider_infos.push(info),
            Err(_) => provider_infos.push(None),
        }
    }

    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price_uakt as f64 / 1_000_000.0;
        let info = &provider_infos[i];

        // Header: index, price
        println!(
            "  [{}] {:.6} AKT/block ({} uakt)",
            i + 1,
            price_akt,
            bid.price_uakt
        );

        // Provider address
        println!("      address:  {}", bid.provider);

        // Host URI
        if let Some(ref info) = info {
            println!("      host:     {}", info.host_uri);

            if !info.email.is_empty() {
                println!("      email:    {}", info.email);
            }
            if !info.website.is_empty() {
                println!("      website:  {}", info.website);
            }

            // Show key attributes (audit, region, tier, etc.)
            let interesting_keys = [
                "host",
                "organization",
                "tier",
                "region",
                "capabilities/storage/3/class",
                "capabilities/gpu/vendor/nvidia/model/*",
            ];

            let audited = info.attributes.iter().any(|(k, _)| k.starts_with("audit-"));

            if audited {
                println!("      audited:  YES");
            }

            let mut shown_attrs = Vec::new();
            for (key, val) in &info.attributes {
                // Show short, useful attributes
                for ik in &interesting_keys {
                    if key.contains(ik) {
                        shown_attrs.push(format!("{}={}", key, val));
                    }
                }
            }
            if !shown_attrs.is_empty() {
                println!("      attrs:    {}", shown_attrs.join(", "));
            }
        } else {
            println!("      host:     (could not query provider info)");
        }

        println!();
    }

    print!("  Select provider (1-{}): ", bids.len());
    io::stdout().flush()?;

    let stdin = io::stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;

    let choice: usize = input
        .trim()
        .parse()
        .map_err(|_| format!("invalid input: '{}'", input.trim()))?;

    if choice < 1 || choice > bids.len() {
        return Err(format!("selection {} out of range (1-{})", choice, bids.len()).into());
    }

    let selected = &bids[choice - 1];
    let selected_info = &provider_infos[choice - 1];

    println!();
    println!("  Selected: {}", selected.provider);
    if let Some(ref info) = selected_info {
        println!("  Host:     {}", info.host_uri);
    }
    println!("═══════════════════════════════════════════════════════════════════════");
    println!();

    Ok(selected.provider.clone())
}

/// Close a deployment. Best-effort — logs errors but doesn't panic.
async fn cleanup_deployment(client: &AkashClient, owner: &str, dseq: u64, signer: &KeySigner) {
    println!("cleanup: closing deployment dseq={}", dseq);
    match client.broadcast_close_deployment(signer, owner, dseq).await {
        Ok(tx) => println!("cleanup: close tx={} code={}", tx.hash, tx.code),
        Err(e) => println!("cleanup: close failed (may already be closed): {}", e),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env
    dotenvy::dotenv().ok();

    // Initialize tracing subscriber.
    // Control verbosity with RUST_LOG env var:
    //   RUST_LOG=info   — see client init steps (default)
    //   RUST_LOG=debug  — see gRPC connection details
    //   RUST_LOG=trace  — see everything (very verbose)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let mnemonic = std::env::var("TEST_MNEMONIC")
        .map_err(|_| "TEST_MNEMONIC not set — set it in .env or environment")?;

    if mnemonic.is_empty() {
        return Err("TEST_MNEMONIC is empty".into());
    }

    println!("═══ Akash Deploy Interactive ═══");
    println!();

    let client = AkashClient::new_from_mnemonic(&mnemonic, &rpc(), &grpc()).await?;
    let owner = client.address();
    println!("  owner: {}", owner);

    let balance = client.query_balance(&owner, "uakt").await?;
    println!();

    let signer = KeySigner::new_mnemonic_str(&mnemonic, None)
        .map_err(|e| format!("failed to create signer: {e:?}"))?;

    let sdl = include_str!("../tests/testdata/permissionless.yaml");

    let mut state = DeploymentState::new("interactive-deploy", &owner)
        .with_sdl(sdl)
        .with_label("interactive-deploy");

    let config = WorkflowConfig {
        auto_select_cheapest_bid: false,
        ..Default::default()
    };
    let workflow = DeploymentWorkflow::new(&client, &signer, config);

    // Run workflow
    let result: Result<(), Box<dyn std::error::Error>> = async {
        for i in 0..60 {
            println!("step {}: {:?}", i, state.step);
            match workflow.advance(&mut state).await? {
                StepResult::Continue => continue,
                StepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    let provider = interactive_select_provider(&bids, &client).await?;
                    DeploymentWorkflow::<AkashClient>::select_provider(&mut state, &provider)?;
                }
                StepResult::NeedsInput(_) => {
                    return Err("unexpected input required".into());
                }
                StepResult::Complete => {
                    println!();
                    println!("═══ Deployment Complete! ═══");
                    if let Some(dseq) = state.dseq {
                        println!("  dseq: {}", dseq);
                    }
                    for ep in &state.endpoints {
                        println!("  endpoint: {} ({}:{})", ep.uri, ep.service, ep.port);
                    }
                    return Ok(());
                }
                StepResult::Failed(reason) => {
                    return Err(format!("workflow failed: {}", reason).into());
                }
            }
        }
        Err("exceeded 60 iterations".into())
    }
    .await;

    // Always cleanup
    if let Some(dseq) = state.dseq {
        cleanup_deployment(&client, &owner, dseq, &signer).await;
    }

    result?;
    Ok(())
}
