# Auto-generated from akash.manifest.v2beta3 — do not edit.
# Source: terp-rs/proto/src/gen/akash.manifest.v2beta3.rs
# Package: akash.manifest.v2beta3
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.manifest.v2beta3"

@dataclass
class ServiceExposeHttpOptions:
    """ServiceExposeHTTPOptions"""
    max_body_size: int = 0
    read_timeout: int = 0
    send_timeout: int = 0
    next_tries: int = 0
    next_timeout: int = 0
    next_cases: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.manifest.v2beta3.ServiceExposeHTTPOptions", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ServiceExposeHttpOptions":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ServiceExpose:
    """ServiceExpose stores exposed ports and hosts details"""
    # port on the container
    port: int = 0
    # port on the service definition
    external_port: int = 0
    proto: str = ""
    service: str = ""
    global: bool = False
    hosts: List[str] = field(default_factory=list)
    http_options: Optional[ServiceExposeHttpOptions] = None
    # The name of the IP address associated with this, if any
    ip: str = ""
    # The sequence number of the associated endpoint in the on-chain data
    endpoint_sequence_number: int = 0
    TYPE_URL: str = field(default="/akash.manifest.v2beta3.ServiceExpose", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ServiceExpose":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class StorageParams:
    """StorageParams"""
    name: str = ""
    mount: str = ""
    read_only: bool = False
    TYPE_URL: str = field(default="/akash.manifest.v2beta3.StorageParams", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "StorageParams":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ServiceParams:
    """ServiceParams"""
    storage: List[StorageParams] = field(default_factory=list)
    credentials: Optional[ImageCredentials] = None
    TYPE_URL: str = field(default="/akash.manifest.v2beta3.ServiceParams", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ServiceParams":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ImageCredentials:
    """Credentials to fetch image from registry"""
    host: str = ""
    email: str = ""
    username: str = ""
    password: str = ""
    TYPE_URL: str = field(default="/akash.manifest.v2beta3.ImageCredentials", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ImageCredentials":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Service:
    """Service stores name, image, args, env, unit, count and expose list of service"""
    name: str = ""
    image: str = ""
    command: List[str] = field(default_factory=list)
    args: List[str] = field(default_factory=list)
    env: List[str] = field(default_factory=list)
    resources: Optional[Any  # Any] = None
    count: int = 0
    expose: List[ServiceExpose] = field(default_factory=list)
    params: Optional[ServiceParams] = None
    credentials: Optional[ImageCredentials] = None
    TYPE_URL: str = field(default="/akash.manifest.v2beta3.Service", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Service":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Group:
    """Group store name and list of services"""
    name: str = ""
    services: List[Service] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.manifest.v2beta3.Group", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Group":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

