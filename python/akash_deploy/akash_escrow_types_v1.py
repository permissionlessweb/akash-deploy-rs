# Auto-generated from akash.escrow.types.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.escrow.types.v1.rs
# Package: akash.escrow.types.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.escrow.types.v1"

@dataclass
class Balance:
    """Balance holds the unspent coin received from all deposits with same denom DecCoin is not being used here as it does not support negative values, and balance may go negative if account is overdrawn."""
    denom: str = ""
    amount: str = ""
    TYPE_URL: str = field(default="/akash.escrow.types.v1.Balance", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Balance":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Depositor:
    """Depositor stores state of a deposit."""
    # Owner is the bech32 address of the depositor. It is a string representing a valid account address.  Example: "akash1..." If depositor is same as the owner, then any incoming coins are added to the Balance. If depositor isn't same as the owner, then any incoming coins are added to the Funds.
    owner: str = ""
    # Height blockchain height at which deposit was created
    height: str = "0"
    # Source indicated origination of the funds
    source: int = 0
    # Balance amount of funds available to spend in this deposit.
    balance: Optional[Any  # Any] = None
    # direct indicates if deposited currency should be swapped to ACT (false) at time of the deposit
    direct: bool = False
    TYPE_URL: str = field(default="/akash.escrow.types.v1.Depositor", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Depositor":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class AccountState:
    """Account stores state for an escrow account."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # State represents the current state of an Account.
    state: int = 0
    # Transferred total coins spent by this account.
    transferred: List[Any] = field(default_factory=list)
    # SettledAt represents the block height at which this account was last settled.
    settled_at: str = "0"
    # Funds holds the unspent coins received from all deposits
    funds: List[Balance] = field(default_factory=list)
    deposits: List[Depositor] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.escrow.types.v1.AccountState", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "AccountState":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Account:
    """Account"""
    id: Optional[Account] = None
    state: Optional[AccountState] = None
    TYPE_URL: str = field(default="/akash.escrow.types.v1.Account", init=False, repr=False)

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
class PaymentState:
    """Payment stores state for a payment."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # State represents the state of the Payment.
    state: int = 0
    # Rate holds the rate of the Payment.
    rate: Optional[Any  # Any] = None
    # Balance is the current available coins.
    balance: Optional[Any  # Any] = None
    # Unsettled is the amount needed to settle payment if account is overdrawn
    unsettled: Optional[Any  # Any] = None
    # Withdrawn corresponds to the amount of coins withdrawn by the Payment.
    withdrawn: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.escrow.types.v1.PaymentState", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PaymentState":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Payment:
    """Payment"""
    id: Optional[Payment] = None
    state: Optional[PaymentState] = None
    TYPE_URL: str = field(default="/akash.escrow.types.v1.Payment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Payment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

