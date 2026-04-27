//! Cosmos SDK AuthZ + FeeGrant delegation for Akash deployment lifecycle.
//!
//! Enables a "deployer" wallet (grantee) to execute deployment operations
//! on behalf of a main wallet (granter) without holding the granter's keys.
//! Combined with FeeGrant, the granter pays all gas fees.

use layer_climb::proto::Any;
use prost::{Message as ProstMessage, Name as ProstName};
use serde::{Deserialize, Serialize};

use crate::gen::akash::{
    cert::v1 as akash_cert,
    deployment::v1beta4 as akash_deployment,
    escrow::v1 as akash_escrow,
    market::v1beta5 as akash_market,
};

// ── Type URL derivation ─────────────────────────────────────────────────

/// Returns the Akash deployment lifecycle message type URLs for AuthZ grants.
///
/// Derived from prost-generated `type_url()` — never hardcoded.
/// If proto versions change (e.g. v1beta4 → v1beta5), these update at compile time.
pub fn authz_msg_type_urls() -> Vec<String> {
    vec![
        <akash_deployment::MsgCreateDeployment as ProstName>::type_url(),
        <akash_deployment::MsgCloseDeployment as ProstName>::type_url(),
        <akash_market::MsgCreateLease as ProstName>::type_url(),
        <akash_escrow::MsgAccountDeposit as ProstName>::type_url(),
        <akash_cert::MsgCreateCertificate as ProstName>::type_url(),
    ]
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Convert a prost message into a `layer_climb::proto::Any`.
fn to_any<M: ProstMessage + ProstName>(msg: &M) -> Any {
    Any {
        type_url: M::type_url(),
        value: msg.encode_to_vec(),
    }
}

// ── AuthZ Grant Builders ────────────────────────────────────────────────

/// Build `MsgGrant` messages — one per deployment lifecycle message type.
///
/// Each grant wraps a `GenericAuthorization` for the specific msg type URL.
/// All grants can be batched into a single transaction.
///
/// `expiration` is an optional Unix timestamp (seconds). If `None`, grants
/// do not expire (use with caution).
pub fn build_authz_grant_msgs(
    granter: &str,
    grantee: &str,
    expiration: Option<u64>,
) -> Vec<Any> {
    use layer_climb::proto::authz::{GenericAuthorization, Grant, MsgGrant};

    let exp_timestamp = expiration.map(|ts| layer_climb::proto::Timestamp {
        seconds: ts as i64,
        nanos: 0,
    });

    authz_msg_type_urls()
        .into_iter()
        .map(|msg_type_url| {
            let authorization = GenericAuthorization {
                msg: msg_type_url,
            };

            let grant = Grant {
                authorization: Some(to_any(&authorization)),
                expiration: exp_timestamp.clone(),
            };

            let msg = MsgGrant {
                granter: granter.to_string(),
                grantee: grantee.to_string(),
                grant: Some(grant),
            };

            to_any(&msg)
        })
        .collect()
}

/// Build a `MsgGrantAllowance` for fee delegation.
///
/// Wraps a `BasicAllowance` (with optional spend limit + expiration) inside
/// an `AllowedMsgAllowance` restricted to deployment lifecycle messages only.
/// This ensures the fee grant cannot be used for arbitrary transaction types.
pub fn build_feegrant_msg(
    granter: &str,
    grantee: &str,
    spend_limit_uakt: Option<u64>,
    expiration: Option<u64>,
) -> Any {
    use layer_climb::proto::feegrant::{AllowedMsgAllowance, BasicAllowance, MsgGrantAllowance};

    let exp_timestamp = expiration.map(|ts| layer_climb::proto::Timestamp {
        seconds: ts as i64,
        nanos: 0,
    });

    let basic = BasicAllowance {
        spend_limit: spend_limit_uakt
            .map(|amount| {
                vec![layer_climb::proto::Coin {
                    denom: "uakt".to_string(),
                    amount: amount.to_string(),
                }]
            })
            .unwrap_or_default(),
        expiration: exp_timestamp,
    };

    // The fee grant must allow MsgExec (the outer message the grantee broadcasts)
    // in addition to the inner deployment message types.
    let mut allowed_messages = authz_msg_type_urls();
    allowed_messages.push(<layer_climb::proto::authz::MsgExec as ProstName>::type_url());

    let allowed = AllowedMsgAllowance {
        allowance: Some(to_any(&basic)),
        allowed_messages,
    };

    let msg = MsgGrantAllowance {
        granter: granter.to_string(),
        grantee: grantee.to_string(),
        allowance: Some(to_any(&allowed)),
    };

    to_any(&msg)
}

// ── MsgExec Wrapping ────────────────────────────────────────────────────

/// Wrap inner messages in a `MsgExec` for delegated execution.
///
/// The grantee signs the outer transaction; the inner messages execute
/// as if signed by the granter. Each inner message's `owner`/`sender`
/// field must be the granter's address.
pub fn wrap_in_msg_exec(grantee_addr: &str, inner_msgs: &[Any]) -> Any {
    use layer_climb::proto::authz::MsgExec;

    let msg = MsgExec {
        grantee: grantee_addr.to_string(),
        msgs: inner_msgs.to_vec(),
    };

    to_any(&msg)
}

// ── Revoke Builders ─────────────────────────────────────────────────────

/// Build `MsgRevoke` messages — one per granted message type.
pub fn build_authz_revoke_msgs(granter: &str, grantee: &str) -> Vec<Any> {
    use layer_climb::proto::authz::MsgRevoke;

    authz_msg_type_urls()
        .into_iter()
        .map(|msg_type_url| {
            let msg = MsgRevoke {
                granter: granter.to_string(),
                grantee: grantee.to_string(),
                msg_type_url,
            };
            to_any(&msg)
        })
        .collect()
}

/// Build a `MsgRevokeAllowance` to remove the fee grant.
pub fn build_feegrant_revoke_msg(granter: &str, grantee: &str) -> Any {
    use layer_climb::proto::feegrant::MsgRevokeAllowance;

    let msg = MsgRevokeAllowance {
        granter: granter.to_string(),
        grantee: grantee.to_string(),
    };

    to_any(&msg)
}

// ── AuthZ Config (serializable metadata) ────────────────────────────────

/// Persistent metadata about an active AuthZ delegation.
///
/// Saved alongside the deployer key so the CLI knows the granter address,
/// granted message types, and expiration without querying on-chain.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthzConfig {
    pub granter_address: String,
    pub grantee_address: String,
    /// Message type URLs that were granted (derived from `authz_msg_type_urls()`).
    pub msg_types: Vec<String>,
    /// Optional grant expiration (Unix timestamp in seconds).
    pub expiration: Option<u64>,
    /// Optional fee grant spend limit in uakt.
    pub fee_spend_limit: Option<u64>,
    /// When the grants were created (Unix timestamp).
    pub created_at: u64,
}

impl AuthzConfig {
    /// Check if the grants have expired based on the current time.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expiration {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now >= exp
        } else {
            false
        }
    }
}
