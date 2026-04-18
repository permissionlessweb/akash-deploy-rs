# Auto-generated from console.dashboard — do not edit.
# Source: terp-rs/proto/src/gen/console.dashboard.rs
# Package: console.dashboard
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "console.dashboard"

@dataclass
class GetDashboardDataRequest:
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseChainStats:
    height: float = 0.0
    transaction_count: float = 0.0
    bonded_tokens: float = 0.0
    total_supply: float = 0.0
    community_pool: float = 0.0
    inflation: float = 0.0
    staking_apr: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseChainStats", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseChainStats":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseNow:
    date: str = ""
    height: float = 0.0
    active_lease_count: float = 0.0
    total_lease_count: float = 0.0
    daily_lease_count: float = 0.0
    total_u_akt_spent: float = 0.0
    daily_u_akt_spent: float = 0.0
    total_u_act_spent: float = 0.0
    daily_u_act_spent: float = 0.0
    total_u_usdc_spent: float = 0.0
    daily_u_usdc_spent: float = 0.0
    total_u_usd_spent: float = 0.0
    daily_u_usd_spent: float = 0.0
    active_cpu: float = 0.0
    active_gpu: float = 0.0
    active_memory: float = 0.0
    active_storage: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseNow", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseNow":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseCompare:
    date: str = ""
    height: float = 0.0
    active_lease_count: float = 0.0
    total_lease_count: float = 0.0
    daily_lease_count: float = 0.0
    total_u_akt_spent: float = 0.0
    daily_u_akt_spent: float = 0.0
    total_u_act_spent: float = 0.0
    daily_u_act_spent: float = 0.0
    total_u_usdc_spent: float = 0.0
    daily_u_usdc_spent: float = 0.0
    total_u_usd_spent: float = 0.0
    daily_u_usd_spent: float = 0.0
    active_cpu: float = 0.0
    active_gpu: float = 0.0
    active_memory: float = 0.0
    active_storage: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseCompare", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseCompare":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseNetworkCapacity:
    active_provider_count: float = 0.0
    active_cpu: float = 0.0
    active_gpu: float = 0.0
    active_memory: float = 0.0
    active_storage: float = 0.0
    pending_cpu: float = 0.0
    pending_gpu: float = 0.0
    pending_memory: float = 0.0
    pending_storage: float = 0.0
    available_cpu: float = 0.0
    available_gpu: float = 0.0
    available_memory: float = 0.0
    available_storage: float = 0.0
    total_cpu: float = 0.0
    total_gpu: float = 0.0
    total_memory: float = 0.0
    total_storage: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseNetworkCapacity", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseNetworkCapacity":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseNetworkCapacityStatsSnapshot:
    date: str = ""
    value: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseNetworkCapacityStatsSnapshot", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseNetworkCapacityStatsSnapshot":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseNetworkCapacityStatsNow:
    count: float = 0.0
    cpu: float = 0.0
    gpu: float = 0.0
    memory: float = 0.0
    storage: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseNetworkCapacityStatsNow", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseNetworkCapacityStatsNow":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseNetworkCapacityStatsCompare:
    count: float = 0.0
    cpu: float = 0.0
    gpu: float = 0.0
    memory: float = 0.0
    storage: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseNetworkCapacityStatsCompare", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseNetworkCapacityStatsCompare":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseNetworkCapacityStats:
    current_value: float = 0.0
    compare_value: float = 0.0
    snapshots: List[Any] = field(default_factory=list)
    now: Optional[GetDashboardDataResponseNetworkCapacityStatsNow] = None
    compare: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseNetworkCapacityStats", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseNetworkCapacityStats":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseLatestBlockProposer:
    address: str = ""
    operator_address: str = ""
    moniker: str = ""
    avatar_url: str = ""
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseLatestBlockProposer", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseLatestBlockProposer":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseLatestBlock:
    height: float = 0.0
    transaction_count: float = 0.0
    total_transaction_count: float = 0.0
    datetime: str = ""
    proposer: Optional[GetDashboardDataResponseLatestBlockProposer] = None
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseLatestBlock", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseLatestBlock":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseLatestTransactionMessage:
    id: str = ""
    amount: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseLatestTransactionMessage", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseLatestTransactionMessage":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponseLatestTransaction:
    height: float = 0.0
    datetime: str = ""
    hash: str = ""
    is_success: bool = False
    error: str = ""
    gas_used: float = 0.0
    gas_wanted: float = 0.0
    fee: float = 0.0
    memo: str = ""
    messages: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponseLatestTransaction", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponseLatestTransaction":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetDashboardDataResponse:
    chain_stats: Optional[GetDashboardDataResponseChainStats] = None
    now: Optional[GetDashboardDataResponseNow] = None
    compare: Optional[GetDashboardDataResponseCompare] = None
    network_capacity: Optional[Any  # Any] = None
    network_capacity_stats: Optional[Any  # Any] = None
    latest_blocks: List[GetDashboardDataResponseLatestBlock] = field(default_factory=list)
    latest_transactions: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.dashboard.GetDashboardDataResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetDashboardDataResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetGraphDataRequest:
    data_name: str = ""
    TYPE_URL: str = field(default="/console.dashboard.GetGraphDataRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetGraphDataRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetGraphDataResponseSnapshot:
    date: str = ""
    value: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetGraphDataResponseSnapshot", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetGraphDataResponseSnapshot":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetGraphDataResponse:
    current_value: float = 0.0
    compare_value: float = 0.0
    snapshots: List[GetGraphDataResponseSnapshot] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.dashboard.GetGraphDataResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetGraphDataResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityRequest:
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResourcesCpu:
    active: float = 0.0
    pending: float = 0.0
    available: float = 0.0
    total: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResourcesCpu", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResourcesCpu":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResourcesGpu:
    active: float = 0.0
    pending: float = 0.0
    available: float = 0.0
    total: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResourcesGpu", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResourcesGpu":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResourcesMemory:
    active: float = 0.0
    pending: float = 0.0
    available: float = 0.0
    total: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResourcesMemory", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResourcesMemory":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResourcesStorageEphemeral:
    active: float = 0.0
    pending: float = 0.0
    available: float = 0.0
    total: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResourcesStorageEphemeral", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResourcesStorageEphemeral":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResourcesStoragePersistent:
    active: float = 0.0
    pending: float = 0.0
    available: float = 0.0
    total: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResourcesStoragePersistent", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResourcesStoragePersistent":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResourcesStorageTotal:
    active: float = 0.0
    pending: float = 0.0
    available: float = 0.0
    total: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResourcesStorageTotal", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResourcesStorageTotal":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResourcesStorage:
    ephemeral: Optional[Any  # Any] = None
    persistent: Optional[Any  # Any] = None
    total: Optional[GetNetworkCapacityResponseResourcesStorageTotal] = None
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResourcesStorage", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResourcesStorage":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponseResources:
    cpu: Optional[GetNetworkCapacityResponseResourcesCpu] = None
    gpu: Optional[GetNetworkCapacityResponseResourcesGpu] = None
    memory: Optional[GetNetworkCapacityResponseResourcesMemory] = None
    storage: Optional[GetNetworkCapacityResponseResourcesStorage] = None
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponseResources", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponseResources":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetNetworkCapacityResponse:
    active_provider_count: float = 0.0
    resources: Optional[GetNetworkCapacityResponseResources] = None
    TYPE_URL: str = field(default="/console.dashboard.GetNetworkCapacityResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetNetworkCapacityResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetMarketDataRequest:
    coin: str = ""
    TYPE_URL: str = field(default="/console.dashboard.GetMarketDataRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetMarketDataRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetMarketDataResponse:
    price: float = 0.0
    volume: float = 0.0
    market_cap: float = 0.0
    market_cap_rank: float = 0.0
    price_change24h: float = 0.0
    price_change_percentage24: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetMarketDataResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetMarketDataResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetBmeDashboardDataRequest:
    TYPE_URL: str = field(default="/console.dashboard.GetBmeDashboardDataRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetBmeDashboardDataRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetBmeDashboardDataResponseNow:
    date: str = ""
    outstanding_act: float = 0.0
    vault_akt: float = 0.0
    collateral_ratio: float = 0.0
    daily_akt_burned_for_act: float = 0.0
    total_akt_burned_for_act: float = 0.0
    daily_act_minted: float = 0.0
    total_act_minted: float = 0.0
    daily_act_burned_for_akt: float = 0.0
    total_act_burned_for_akt: float = 0.0
    daily_akt_reminted: float = 0.0
    total_akt_reminted: float = 0.0
    daily_net_akt_burned: float = 0.0
    net_akt_burned: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetBmeDashboardDataResponseNow", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetBmeDashboardDataResponseNow":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetBmeDashboardDataResponseCompare:
    date: str = ""
    outstanding_act: float = 0.0
    vault_akt: float = 0.0
    collateral_ratio: float = 0.0
    daily_akt_burned_for_act: float = 0.0
    total_akt_burned_for_act: float = 0.0
    daily_act_minted: float = 0.0
    total_act_minted: float = 0.0
    daily_act_burned_for_akt: float = 0.0
    total_act_burned_for_akt: float = 0.0
    daily_akt_reminted: float = 0.0
    total_akt_reminted: float = 0.0
    daily_net_akt_burned: float = 0.0
    net_akt_burned: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetBmeDashboardDataResponseCompare", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetBmeDashboardDataResponseCompare":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetBmeDashboardDataResponse:
    now: Optional[GetBmeDashboardDataResponseNow] = None
    compare: Optional[GetBmeDashboardDataResponseCompare] = None
    TYPE_URL: str = field(default="/console.dashboard.GetBmeDashboardDataResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetBmeDashboardDataResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetBmeStatusHistoryRequest:
    TYPE_URL: str = field(default="/console.dashboard.GetBmeStatusHistoryRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetBmeStatusHistoryRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetBmeStatusHistoryResponseDatum:
    height: float = 0.0
    date: str = ""
    previous_status: str = ""
    new_status: str = ""
    collateral_ratio: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetBmeStatusHistoryResponseDatum", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetBmeStatusHistoryResponseDatum":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetBmeStatusHistoryResponse:
    data: List[GetBmeStatusHistoryResponseDatum] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.dashboard.GetBmeStatusHistoryResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetBmeStatusHistoryResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetLeasesDurationRequest:
    owner: str = ""
    TYPE_URL: str = field(default="/console.dashboard.GetLeasesDurationRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetLeasesDurationRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetLeasesDurationResponseLease:
    dseq: str = ""
    oseq: float = 0.0
    gseq: float = 0.0
    provider: str = ""
    start_height: float = 0.0
    start_date: str = ""
    closed_height: float = 0.0
    closed_date: str = ""
    duration_in_blocks: float = 0.0
    duration_in_seconds: float = 0.0
    duration_in_hours: float = 0.0
    TYPE_URL: str = field(default="/console.dashboard.GetLeasesDurationResponseLease", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetLeasesDurationResponseLease":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetLeasesDurationResponse:
    lease_count: float = 0.0
    total_duration_in_seconds: float = 0.0
    total_duration_in_hours: float = 0.0
    leases: List[GetLeasesDurationResponseLease] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.dashboard.GetLeasesDurationResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetLeasesDurationResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

