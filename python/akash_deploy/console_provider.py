# Auto-generated from console.provider — do not edit.
# Source: terp-rs/proto/src/gen/console.provider.rs
# Package: console.provider
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "console.provider"

@dataclass
class ListProvidersRequest:
    TYPE_URL: str = field(default="/console.provider.ListProvidersRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListProvidersRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ListProvidersResponseProviderGpuModel:
    vendor: str = ""
    model: str = ""
    ram: str = ""
    interface: str = ""
    TYPE_URL: str = field(default="/console.provider.ListProvidersResponseProviderGpuModel", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListProvidersResponseProviderGpuModel":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ListProvidersResponseProviderAttribute:
    key: str = ""
    value: str = ""
    audited_by: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.ListProvidersResponseProviderAttribute", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListProvidersResponseProviderAttribute":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ListProvidersResponseProvider:
    owner: str = ""
    name: str = ""
    host_uri: str = ""
    created_height: float = 0.0
    email: str = ""
    website: str = ""
    last_check_date: str = ""
    deployment_count: float = 0.0
    lease_count: float = 0.0
    cosmos_sdk_version: str = ""
    akash_version: str = ""
    ip_region: str = ""
    ip_region_code: str = ""
    ip_country: str = ""
    ip_country_code: str = ""
    ip_lat: str = ""
    ip_lon: str = ""
    uptime1d: float = 0.0
    uptime7d: float = 0.0
    uptime30d: float = 0.0
    is_valid_version: bool = False
    is_online: bool = False
    last_online_date: str = ""
    is_audited: bool = False
    gpu_models: List[ListProvidersResponseProviderGpuModel] = field(default_factory=list)
    attributes: List[ListProvidersResponseProviderAttribute] = field(default_factory=list)
    host: str = ""
    organization: str = ""
    status_page: str = ""
    location_region: str = ""
    country: str = ""
    city: str = ""
    timezone: str = ""
    location_type: str = ""
    hosting_provider: str = ""
    hardware_cpu: str = ""
    hardware_cpu_arch: str = ""
    hardware_gpu_vendor: str = ""
    hardware_gpu_models: List[str] = field(default_factory=list)
    hardware_disk: List[str] = field(default_factory=list)
    feat_persistent_storage: bool = False
    feat_persistent_storage_type: List[str] = field(default_factory=list)
    hardware_memory: str = ""
    network_provider: str = ""
    network_speed_down: float = 0.0
    network_speed_up: float = 0.0
    tier: str = ""
    feat_endpoint_custom_domain: bool = False
    workload_support_chia: bool = False
    workload_support_chia_capabilities: List[str] = field(default_factory=list)
    feat_endpoint_ip: bool = False
    TYPE_URL: str = field(default="/console.provider.ListProvidersResponseProvider", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListProvidersResponseProvider":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ListProvidersResponse:
    providers: List[ListProvidersResponseProvider] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.ListProvidersResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ListProvidersResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderRequest:
    address: str = ""
    TYPE_URL: str = field(default="/console.provider.GetProviderRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseStatsCpu:
    active: float = 0.0
    available: float = 0.0
    pending: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseStatsCpu", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseStatsCpu":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseStatsGpu:
    active: float = 0.0
    available: float = 0.0
    pending: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseStatsGpu", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseStatsGpu":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseStatsMemory:
    active: float = 0.0
    available: float = 0.0
    pending: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseStatsMemory", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseStatsMemory":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseStatsStorageEphemeral:
    active: float = 0.0
    available: float = 0.0
    pending: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseStatsStorageEphemeral", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseStatsStorageEphemeral":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseStatsStoragePersistent:
    active: float = 0.0
    available: float = 0.0
    pending: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseStatsStoragePersistent", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseStatsStoragePersistent":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseStatsStorage:
    ephemeral: Optional[GetProviderResponseStatsStorageEphemeral] = None
    persistent: Optional[GetProviderResponseStatsStoragePersistent] = None
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseStatsStorage", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseStatsStorage":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseStats:
    cpu: Optional[GetProviderResponseStatsCpu] = None
    gpu: Optional[GetProviderResponseStatsGpu] = None
    memory: Optional[GetProviderResponseStatsMemory] = None
    storage: Optional[GetProviderResponseStatsStorage] = None
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseStats", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseStats":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseGpuModel:
    vendor: str = ""
    model: str = ""
    ram: str = ""
    interface: str = ""
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseGpuModel", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseGpuModel":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseAttribute:
    key: str = ""
    value: str = ""
    audited_by: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseAttribute", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseAttribute":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponseUptime:
    id: str = ""
    is_online: bool = False
    check_date: str = ""
    TYPE_URL: str = field(default="/console.provider.GetProviderResponseUptime", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponseUptime":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderResponse:
    owner: str = ""
    name: str = ""
    host_uri: str = ""
    created_height: float = 0.0
    email: str = ""
    website: str = ""
    last_check_date: str = ""
    deployment_count: float = 0.0
    lease_count: float = 0.0
    cosmos_sdk_version: str = ""
    akash_version: str = ""
    ip_region: str = ""
    ip_region_code: str = ""
    ip_country: str = ""
    ip_country_code: str = ""
    ip_lat: str = ""
    ip_lon: str = ""
    uptime1d: float = 0.0
    uptime7d: float = 0.0
    uptime30d: float = 0.0
    is_valid_version: bool = False
    is_online: bool = False
    last_online_date: str = ""
    is_audited: bool = False
    stats: Optional[GetProviderResponseStats] = None
    gpu_models: List[GetProviderResponseGpuModel] = field(default_factory=list)
    attributes: List[GetProviderResponseAttribute] = field(default_factory=list)
    host: str = ""
    organization: str = ""
    status_page: str = ""
    location_region: str = ""
    country: str = ""
    city: str = ""
    timezone: str = ""
    location_type: str = ""
    hosting_provider: str = ""
    hardware_cpu: str = ""
    hardware_cpu_arch: str = ""
    hardware_gpu_vendor: str = ""
    hardware_gpu_models: List[str] = field(default_factory=list)
    hardware_disk: List[str] = field(default_factory=list)
    feat_persistent_storage: bool = False
    feat_persistent_storage_type: List[str] = field(default_factory=list)
    hardware_memory: str = ""
    network_provider: str = ""
    network_speed_down: float = 0.0
    network_speed_up: float = 0.0
    tier: str = ""
    feat_endpoint_custom_domain: bool = False
    workload_support_chia: bool = False
    workload_support_chia_capabilities: List[str] = field(default_factory=list)
    feat_endpoint_ip: bool = False
    uptime: List[GetProviderResponseUptime] = field(default_factory=list)
    TYPE_URL: str = field(default="/console.provider.GetProviderResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderActiveLeasesGraphRequest:
    provider_address: str = ""
    TYPE_URL: str = field(default="/console.provider.GetProviderActiveLeasesGraphRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderActiveLeasesGraphRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderActiveLeasesGraphResponseSnapshot:
    date: str = ""
    value: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderActiveLeasesGraphResponseSnapshot", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderActiveLeasesGraphResponseSnapshot":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderActiveLeasesGraphResponseNow:
    count: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderActiveLeasesGraphResponseNow", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderActiveLeasesGraphResponseNow":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderActiveLeasesGraphResponseCompare:
    count: float = 0.0
    TYPE_URL: str = field(default="/console.provider.GetProviderActiveLeasesGraphResponseCompare", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderActiveLeasesGraphResponseCompare":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetProviderActiveLeasesGraphResponse:
    current_value: float = 0.0
    compare_value: float = 0.0
    snapshots: List[Any] = field(default_factory=list)
    now: Optional[GetProviderActiveLeasesGraphResponseNow] = None
    compare: Optional[GetProviderActiveLeasesGraphResponseCompare] = None
    TYPE_URL: str = field(default="/console.provider.GetProviderActiveLeasesGraphResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetProviderActiveLeasesGraphResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetJwtTokenRequest:
    provider: str = ""
    TYPE_URL: str = field(default="/console.provider.GetJwtTokenRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetJwtTokenRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetJwtTokenResponseData:
    token: str = ""
    TYPE_URL: str = field(default="/console.provider.GetJwtTokenResponseData", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetJwtTokenResponseData":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GetJwtTokenResponse:
    data: Optional[GetJwtTokenResponseData] = None
    TYPE_URL: str = field(default="/console.provider.GetJwtTokenResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GetJwtTokenResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

