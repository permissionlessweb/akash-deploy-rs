# Auto-generated from akash.escrow.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.escrow.v1.rs
# Package: akash.escrow.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.escrow.v1"

@dataclass
class QueryAccountsRequest:
    """QueryAccountRequest is request type for the Query/Account RPC method."""
    # State represents the current state of an Account.
    state: str = ""
    # Scope holds the scope of the account.
    xid: str = ""
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1.QueryAccountsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryAccountsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryAccountsResponse:
    """QueryProvidersResponse is response type for the Query/Providers RPC method"""
    # Accounts is a list of Account.
    accounts: List[Account] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1.QueryAccountsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryAccountsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryPaymentsRequest:
    """QueryPaymentRequest is request type for the Query/Payment RPC method"""
    # State represents the current state of a Payment.
    state: str = ""
    xid: str = ""
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1.QueryPaymentsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryPaymentsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryPaymentsResponse:
    """QueryProvidersResponse is response type for the Query/Providers RPC method"""
    # Payments is a list of payments.
    payments: List[Payment] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1.QueryPaymentsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryPaymentsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgAccountDeposit:
    """MsgAccountDeposit represents a message to deposit funds into an existing escrow account on the blockchain. This is part of the interaction mechanism for managing deployment-related resources."""
    # Signer is the account bech32 address of the user who wants to deposit into an escrow account. Does not necessarily needs to be an owner of the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    signer: str = ""
    # ID is the unique identifier of the account.
    id: Optional[Any  # Account] = None
    # Deposit contains information about the deposit amount and the source of the deposit to the escrow account.
    deposit: Optional[Any  # Deposit] = None
    TYPE_URL: str = field(default="/akash.escrow.v1.MsgAccountDeposit", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgAccountDeposit":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgAccountDepositResponse:
    """MsgAccountDepositResponse defines response type for the MsgDeposit."""
    TYPE_URL: str = field(default="/akash.escrow.v1.MsgAccountDepositResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgAccountDepositResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class DepositAuthorization:
    """DepositAuthorization allows the grantee to deposit up to spend_limit coins from the granter's account for Akash deployments and bids. This authorization is used within the Cosmos SDK authz module to grant scoped permissions for deposit operations. The authorization can be restricted to specific scopes (deployment or bid) to limit what types of deposits the grantee is authorized to make on behalf of the granter."""
    # SpendLimit is the maximum amount the grantee is authorized to spend from the granter's account. This limit applies cumulatively across all deposit operations within the authorized scopes. Once this limit is reached, the authorization becomes invalid and no further deposits can be made.
    spend_limit: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1.DepositAuthorization", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "DepositAuthorization":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the basic genesis state used by the escrow module."""
    # Accounts is a list of accounts on the genesis state.
    accounts: List[Account] = field(default_factory=list)
    # Payments is a list of fractional payments on the genesis state..
    payments: List[Payment] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.escrow.v1.GenesisState", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisState":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

