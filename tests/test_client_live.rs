//! Live integration tests for AkashClient.
//!
//! These tests require a funded Akash account and live network access.
//! Set `TEST_MNEMONIC` in `.env` or environment to run them.
//! Without credentials, tests skip gracefully.

#![cfg(feature = "default-client")]

use akash_deploy_rs::{
    AkashBackend, AkashClient, DeploymentState, DeploymentWorkflow, InputRequired, KeySigner,
    Step, StepResult, WorkflowConfig,
};
use std::io::{self, BufRead, Write};

const DEFAULT_RPC: &str = "https://rpc-akash.ecostake.com:443";
const DEFAULT_GRPC: &str = "https://grpc.akashnet.net:443";

/// Load .env and return TEST_MNEMONIC, or None to skip.
fn test_mnemonic() -> Option<String> {
    dotenvy::dotenv().ok();
    match std::env::var("TEST_MNEMONIC") {
        Ok(m) if !m.is_empty() => Some(m),
        _ => {
            eprintln!("TEST_MNEMONIC not set — skipping integration test");
            None
        }
    }
}

fn test_rpc() -> String {
    std::env::var("TEST_RPC_ENDPOINT").unwrap_or_else(|_| DEFAULT_RPC.to_string())
}

fn test_grpc() -> String {
    std::env::var("TEST_GRPC_ENDPOINT").unwrap_or_else(|_| DEFAULT_GRPC.to_string())
}

/// Close a deployment. Best-effort — logs errors but doesn't fail.
async fn cleanup_deployment(client: &AkashClient, owner: &str, dseq: u64, signer: &KeySigner) {
    eprintln!("cleanup: closing deployment dseq={}", dseq);
    match client
        .broadcast_close_deployment(signer, owner, dseq)
        .await
    {
        Ok(tx) => eprintln!("cleanup: close tx={} code={}", tx.hash, tx.code),
        Err(e) => eprintln!("cleanup: close failed (may already be closed): {}", e),
    }
}

/// Interactively prompt user to select a provider from available bids.
fn interactive_select_provider(
    bids: &[akash_deploy_rs::Bid],
) -> Result<String, Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("═══════════════════════════════════════════════════════════");
    eprintln!("  PROVIDER SELECTION — {} bid(s) received", bids.len());
    eprintln!("═══════════════════════════════════════════════════════════");
    eprintln!();

    for (i, bid) in bids.iter().enumerate() {
        let price_akt = bid.price_uakt as f64 / 1_000_000.0;
        eprintln!(
            "  [{}] {} — {:.6} AKT/block ({} uakt)",
            i + 1,
            bid.provider,
            price_akt,
            bid.price_uakt
        );
    }

    eprintln!();
    eprint!("  Select provider (1-{}): ", bids.len());
    io::stderr().flush()?;

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
    eprintln!();
    eprintln!("  Selected: {}", selected.provider);
    eprintln!("═══════════════════════════════════════════════════════════");
    eprintln!();

    Ok(selected.provider.clone())
}

#[tokio::test]
async fn test_client_query_balance() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = match test_mnemonic() {
        Some(m) => m,
        None => return Ok(()),
    };

    let client = AkashClient::new_from_mnemonic(&mnemonic, &test_rpc(), &test_grpc()).await?;
    let address = client.address();
    eprintln!("address: {}", address);

    let balance = client.query_balance(&address, "uakt").await?;
    eprintln!("balance: {} uakt", balance);

    // Verify we get a non-error response — balance could be 0
    assert!(balance < u128::MAX, "balance should be a real number");
    Ok(())
}

#[tokio::test]
async fn test_full_deployment_workflow() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = match test_mnemonic() {
        Some(m) => m,
        None => return Ok(()),
    };

    let client = AkashClient::new_from_mnemonic(&mnemonic, &test_rpc(), &test_grpc()).await?;
    let owner = client.address();
    eprintln!("owner: {}", owner);

    // Create signer for workflow (backend ignores it internally, but type system needs it)
    let signer = KeySigner::new_mnemonic_str(&mnemonic, None)
        .map_err(|e| format!("failed to create signer: {e:?}"))?;

    let sdl = include_str!("testdata/permissionless.yaml");

    let mut state = DeploymentState::new("integration-test", &owner)
        .with_sdl(sdl)
        .with_label("integration-test");

    // Interactive provider selection (no auto-select to avoid phishing providers)
    let config = WorkflowConfig {
        auto_select_cheapest_bid: false,
        ..Default::default()
    };
    let workflow = DeploymentWorkflow::new(&client, &signer, config);

    // Run workflow, capturing result so we can always cleanup
    let result: Result<(), Box<dyn std::error::Error>> = async {
        for i in 0..60 {
            eprintln!("step {}: {:?}", i, state.step);
            match workflow.advance(&mut state).await? {
                StepResult::Continue => continue,
                StepResult::NeedsInput(InputRequired::SelectProvider { bids }) => {
                    // Interactive: prompt user to select provider
                    let provider = interactive_select_provider(&bids)?;
                    DeploymentWorkflow::<AkashClient>::select_provider(&mut state, &provider)?;
                }
                StepResult::NeedsInput(_) => {
                    return Err("unexpected input required".into());
                }
                StepResult::Complete => {
                    eprintln!("deployment complete!");
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

    // Always cleanup — even on failure
    if let Some(dseq) = state.dseq {
        cleanup_deployment(&client, &owner, dseq, &signer).await;
    }

    // Propagate workflow error
    result?;

    // Assertions
    assert!(state.dseq.is_some(), "dseq should be set");
    assert!(!state.endpoints.is_empty(), "endpoints should not be empty");
    assert!(
        matches!(state.step, Step::Complete),
        "step should be Complete"
    );

    Ok(())
}
