# Auto-generated from akash.escrow.v1beta3 — do not edit.
# Source: terp-rs/proto/src/gen/akash.escrow.v1beta3.rs
# Package: akash.escrow.v1beta3
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.escrow.v1beta3"

@dataclass
class AccountId:
    """AccountID is the account identifier"""
    scope: str = ""
    xid: str = ""
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.AccountID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "AccountId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Account:
    """Account stores state for an escrow account"""
    # unique identifier for this escrow account
    id: Optional[AccountId] = None
    # bech32 encoded account address of the owner of this escrow account
    owner: str = ""
    # current state of this escrow account
    state: int = 0
    # unspent coins received from the owner's wallet
    balance: Optional[Any  # Any] = None
    # total coins spent by this account
    transferred: Optional[Any  # Any] = None
    # block height at which this account was last settled
    settled_at: str = "0"
    # bech32 encoded account address of the depositor. If depositor is same as the owner, then any incoming coins are added to the Balance. If depositor isn't same as the owner, then any incoming coins are added to the Funds.
    depositor: str = ""
    # Funds are unspent coins received from the (non-Owner) Depositor's wallet. If there are any funds, they should be spent before spending the Balance.
    funds: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.Account", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Account":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class FractionalPayment:
    """Payment stores state for a payment"""
    account_id: Optional[AccountId] = None
    payment_id: str = ""
    owner: str = ""
    state: int = 0
    rate: Optional[Any  # Any] = None
    balance: Optional[Any  # Any] = None
    withdrawn: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.FractionalPayment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "FractionalPayment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryAccountsRequest:
    """QueryAccountRequest is request type for the Query/Account RPC method"""
    scope: str = ""
    xid: str = ""
    owner: str = ""
    state: str = ""
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.QueryAccountsRequest", init=False, repr=False)

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
    accounts: List[Account] = field(default_factory=list)
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.QueryAccountsResponse", init=False, repr=False)

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
    scope: str = ""
    xid: str = ""
    id: str = ""
    owner: str = ""
    state: str = ""
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.QueryPaymentsRequest", init=False, repr=False)

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
    payments: List[FractionalPayment] = field(default_factory=list)
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.QueryPaymentsResponse", init=False, repr=False)

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
class GenesisState:
    """GenesisState defines the basic genesis state used by escrow module"""
    accounts: List[Account] = field(default_factory=list)
    payments: List[FractionalPayment] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.escrow.v1beta3.GenesisState", init=False, repr=False)

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

