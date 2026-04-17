"""
akash-deploy: Python bindings for Akash Network proto types.

Includes both on-chain Akash types and Console API types.

Usage:
    from akash_deploy.console_deployment import ListDeploymentsRequest
    from akash_deploy.console_provider import ListProvidersRequest

Low-level encode/decode (requires native extension — run `just py-build`):
    from akash_deploy._native import encode_message, decode_message, registered_types
"""

# Re-export generated modules (populated by `just py-gen`)
try:
    from akash_deploy import (
        console_address,
        console_auth,
        console_bid,
        console_certificate,
        console_deployment,
        console_deployment_settings,
        console_lease,
        console_network,
        console_pricing,
        console_provider,
    )
except ImportError:
    # Generated modules not yet present — run `just py-gen`
    pass

__all__ = [
    "console_address",
    "console_auth",
    "console_bid",
    "console_certificate",
    "console_deployment",
    "console_deployment_settings",
    "console_lease",
    "console_network",
    "console_pricing",
    "console_provider",
]
