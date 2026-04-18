# Auto-generated from console.address — do not edit.
# Source: terp-rs/proto/src/gen/console.address.rs
# Package: console.address
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "console.address"

@dataclass
class GetAddressRequest:
    address: str = ""
    TYPE_URL: str = field(default="/console.address.GetAddressRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseDelegationValidator:
    address: str = ""
    moniker: str = ""
    operator_address: str = ""
    avatar_url: str = ""
    TYPE_URL: str = field(default="/console.address.GetAddressResponseDelegationValidator", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseDelegationValidator":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseDelegation:
    validator: Optional[GetAddressResponseDelegationValidator] = None
    amount: float = 0.0
    reward: float = 0.0
    TYPE_URL: str = field(default="/console.address.GetAddressResponseDelegation", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseDelegation":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseAsset:
    symbol: str = ""
    ibc_token: str = ""
    logo_url: str = ""
    description: str = ""
    amount: float = 0.0
    TYPE_URL: str = field(default="/console.address.GetAddressResponseAsset", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseAsset":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseRedelegationSrcAddress:
    address: str = ""
    moniker: str = ""
    operator_address: str = ""
    avatar_url: str = ""
    TYPE_URL: str = field(default="/console.address.GetAddressResponseRedelegationSrcAddress", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseRedelegationSrcAddress":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseRedelegationDstAddress:
    address: str = ""
    moniker: str = ""
    operator_address: str = ""
    avatar_url: str = ""
    TYPE_URL: str = field(default="/console.address.GetAddressResponseRedelegationDstAddress", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseRedelegationDstAddress":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseRedelegation:
    src_address: Optional[GetAddressResponseRedelegationSrcAddress] = None
    dst_address: Optional[GetAddressResponseRedelegationDstAddress] = None
    creation_height: float = 0.0
    completion_time: str = ""
    amount: float = 0.0
    TYPE_URL: str = field(default="/console.address.GetAddressResponseRedelegation", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseRedelegation":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseLatestTransactionMessage:
    id: str = ""
    amount: float = 0.0
    is_receiver: bool = False
    TYPE_URL: str = field(default="/console.address.GetAddressResponseLatestTransactionMessage", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseLatestTransactionMessage":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponseLatestTransaction:
    height: float = 0.0
    datetime: str = ""
    hash: str = ""
    is_success: bool = False
    error: str = ""
    gas_used: float = 0.0
    gas_wanted: float = 0.0
    fee: float = 0.0
    memo: str = ""
    is_signer: bool = False
    messages: List[GetAddressResponseLatestTransactionMessage] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.address.GetAddressResponseLatestTransaction", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponseLatestTransaction":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressResponse:
    total: float = 0.0
    delegations: List[GetAddressResponseDelegation] = field(default_factory=list)
    available: float = 0.0
    delegated: float = 0.0
    rewards: float = 0.0
    assets: List[GetAddressResponseAsset] = field(default_factory=list)
    redelegations: List[GetAddressResponseRedelegation] = field(default_factory=list)
    commission: float = 0.0
    latest_transactions: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.address.GetAddressResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressTransactionsRequest:
    address: str = ""
    skip: float = 0.0
    limit: float = 0.0
    TYPE_URL: str = field(default="/console.address.GetAddressTransactionsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressTransactionsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressTransactionsResponseResultMessage:
    id: str = ""
    amount: float = 0.0
    is_receiver: bool = False
    TYPE_URL: str = field(default="/console.address.GetAddressTransactionsResponseResultMessage", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressTransactionsResponseResultMessage":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressTransactionsResponseResult:
    height: float = 0.0
    datetime: str = ""
    hash: str = ""
    is_success: bool = False
    error: str = ""
    gas_used: float = 0.0
    gas_wanted: float = 0.0
    fee: float = 0.0
    memo: str = ""
    is_signer: bool = False
    messages: List[GetAddressTransactionsResponseResultMessage] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.address.GetAddressTransactionsResponseResult", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressTransactionsResponseResult":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetAddressTransactionsResponse:
    count: float = 0.0
    results: List[GetAddressTransactionsResponseResult] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.address.GetAddressTransactionsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetAddressTransactionsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

