# Auto-generated from console.provider.extended — do not edit.
# Source: terp-rs/proto/src/gen/console.provider.extended.rs
# Package: console.provider.extended
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "console.provider.extended"

@dataclass
class ListAuditorsRequest:
    TYPE_URL: str = field(default="/console.provider.extended.ListAuditorsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListAuditorsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ListAuditorsResponseDatum:
    id: str = ""
    name: str = ""
    address: str = ""
    website: str = ""
    TYPE_URL: str = field(default="/console.provider.extended.ListAuditorsResponseDatum", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListAuditorsResponseDatum":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ListAuditorsResponse:
    data: List[ListAuditorsResponseDatum] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.extended.ListAuditorsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListAuditorsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class CreateJwtTokenRequest:
    ttl: float = 0.0
    leases: Any = None
    TYPE_URL: str = field(default="/console.provider.extended.CreateJwtTokenRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "CreateJwtTokenRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class CreateJwtTokenResponse:
    token: str = ""
    TYPE_URL: str = field(default="/console.provider.extended.CreateJwtTokenResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "CreateJwtTokenResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDashboardRequest:
    owner: str = ""
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDashboardRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDashboardRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDashboardResponseCurrent:
    date: str = ""
    height: float = 0.0
    active_lease_count: float = 0.0
    total_lease_count: float = 0.0
    daily_lease_count: float = 0.0
    total_u_akt_earned: float = 0.0
    daily_u_akt_earned: float = 0.0
    total_u_usdc_earned: float = 0.0
    daily_u_usdc_earned: float = 0.0
    total_u_act_earned: float = 0.0
    daily_u_act_earned: float = 0.0
    total_u_usd_earned: float = 0.0
    daily_u_usd_earned: float = 0.0
    active_cpu: float = 0.0
    active_gpu: float = 0.0
    active_memory: float = 0.0
    active_ephemeral_storage: float = 0.0
    active_persistent_storage: float = 0.0
    active_storage: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDashboardResponseCurrent", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDashboardResponseCurrent":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDashboardResponsePrevious:
    date: str = ""
    height: float = 0.0
    active_lease_count: float = 0.0
    total_lease_count: float = 0.0
    daily_lease_count: float = 0.0
    total_u_akt_earned: float = 0.0
    daily_u_akt_earned: float = 0.0
    total_u_usdc_earned: float = 0.0
    daily_u_usdc_earned: float = 0.0
    total_u_act_earned: float = 0.0
    daily_u_act_earned: float = 0.0
    total_u_usd_earned: float = 0.0
    daily_u_usd_earned: float = 0.0
    active_cpu: float = 0.0
    active_gpu: float = 0.0
    active_memory: float = 0.0
    active_ephemeral_storage: float = 0.0
    active_persistent_storage: float = 0.0
    active_storage: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDashboardResponsePrevious", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDashboardResponsePrevious":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDashboardResponse:
    current: Optional[GetProviderDashboardResponseCurrent] = None
    previous: Optional[GetProviderDashboardResponsePrevious] = None
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDashboardResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDashboardResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDeploymentsRequest:
    provider: str = ""
    skip: float = 0.0
    limit: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDeploymentsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDeploymentsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDeploymentsResponseDeploymentResources:
    cpu: float = 0.0
    memory: float = 0.0
    gpu: float = 0.0
    ephemeral_storage: float = 0.0
    persistent_storage: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDeploymentsResponseDeploymentResources", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDeploymentsResponseDeploymentResources":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDeploymentsResponseDeploymentLeaseResources:
    cpu: float = 0.0
    memory: float = 0.0
    gpu: float = 0.0
    ephemeral_storage: float = 0.0
    persistent_storage: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDeploymentsResponseDeploymentLeaseResources", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDeploymentsResponseDeploymentLeaseResources":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDeploymentsResponseDeploymentLease:
    provider: str = ""
    gseq: float = 0.0
    oseq: float = 0.0
    price: float = 0.0
    created_height: float = 0.0
    created_date: str = ""
    closed_height: float = 0.0
    closed_date: str = ""
    status: str = ""
    resources: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDeploymentsResponseDeploymentLease", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDeploymentsResponseDeploymentLease":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDeploymentsResponseDeployment:
    owner: str = ""
    dseq: str = ""
    denom: str = ""
    created_height: float = 0.0
    created_date: str = ""
    status: str = ""
    balance: float = 0.0
    transferred: float = 0.0
    settled_at: float = 0.0
    resources: Optional[Any  # Any] = None
    leases: List[GetProviderDeploymentsResponseDeploymentLease] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDeploymentsResponseDeployment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDeploymentsResponseDeployment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderDeploymentsResponse:
    total: float = 0.0
    deployments: List[GetProviderDeploymentsResponseDeployment] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderDeploymentsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderDeploymentsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderEarningsRequest:
    owner: str = ""
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderEarningsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderEarningsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderEarningsResponseEarnings:
    total_u_akt_earned: float = 0.0
    total_u_usdc_earned: float = 0.0
    total_u_act_earned: float = 0.0
    total_u_usd_earned: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderEarningsResponseEarnings", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderEarningsResponseEarnings":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderEarningsResponse:
    earnings: Optional[GetProviderEarningsResponseEarnings] = None
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderEarningsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderEarningsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderGraphDataRequest:
    data_name: str = ""
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderGraphDataRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderGraphDataRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderGraphDataResponseSnapshot:
    date: str = ""
    value: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderGraphDataResponseSnapshot", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderGraphDataResponseSnapshot":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderGraphDataResponseNow:
    count: float = 0.0
    cpu: float = 0.0
    gpu: float = 0.0
    memory: float = 0.0
    storage: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderGraphDataResponseNow", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderGraphDataResponseNow":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderGraphDataResponseCompare:
    count: float = 0.0
    cpu: float = 0.0
    gpu: float = 0.0
    memory: float = 0.0
    storage: float = 0.0
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderGraphDataResponseCompare", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderGraphDataResponseCompare":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderGraphDataResponse:
    current_value: float = 0.0
    compare_value: float = 0.0
    snapshots: List[GetProviderGraphDataResponseSnapshot] = field(default_factory=list)
    now: Optional[GetProviderGraphDataResponseNow] = None
    compare: Optional[GetProviderGraphDataResponseCompare] = None
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderGraphDataResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderGraphDataResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderRegionsRequest:
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderRegionsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderRegionsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderRegionsResponseDatum:
    providers: List[str] = field(default_factory=list)
    key: str = ""
    description: str = ""
    value: str = ""
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderRegionsResponseDatum", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderRegionsResponseDatum":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderRegionsResponse:
    data: List[GetProviderRegionsResponseDatum] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderRegionsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderRegionsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderVersionsRequest:
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderVersionsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderVersionsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderVersionsResponseDatum:
    version: str = ""
    count: float = 0.0
    ratio: float = 0.0
    providers: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderVersionsResponseDatum", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderVersionsResponseDatum":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderVersionsResponse:
    data: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderVersionsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderVersionsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderAttributesSchemaRequest:
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderAttributesSchemaRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderAttributesSchemaRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderAttributesSchemaResponseDatumValue:
    key: str = ""
    description: str = ""
    value: str = ""
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderAttributesSchemaResponseDatumValue", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderAttributesSchemaResponseDatumValue":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderAttributesSchemaResponseDatum:
    key: str = ""
    required: bool = False
    description: str = ""
    values: List[GetProviderAttributesSchemaResponseDatumValue] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderAttributesSchemaResponseDatum", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderAttributesSchemaResponseDatum":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderAttributesSchemaResponse:
    data: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/console.provider.extended.GetProviderAttributesSchemaResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderAttributesSchemaResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

