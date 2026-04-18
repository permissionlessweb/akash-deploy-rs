# Auto-generated from akash.base.resources.v1beta4 — do not edit.
# Source: terp-rs/proto/src/gen/akash.base.resources.v1beta4.rs
# Package: akash.base.resources.v1beta4
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.base.resources.v1beta4"

@dataclass
class ResourceValue:
    """Unit stores cpu, memory and storage metrics."""
    val: str = ""
    TYPE_URL: str = field(default="/akash.base.resources.v1beta4.ResourceValue", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ResourceValue":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Cpu:
    """CPU stores resource units and cpu config attributes."""
    # Units of the CPU, which represents the number of CPUs available. This field is required and must be a non-negative integer.
    units: Optional[ResourceValue] = None
    # Attributes holds a list of key-value attributes that describe the GPU, such as its model, memory and interface. This field is required and must be a list of `Attribute` messages.
    attributes: List[Attribute] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.base.resources.v1beta4.CPU", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Cpu":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Gpu:
    """GPU stores resource units and gpu configuration attributes."""
    # The resource value of the GPU, which represents the number of GPUs available. This field is required and must be a non-negative integer.
    units: Optional[ResourceValue] = None
    attributes: List[Attribute] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.base.resources.v1beta4.GPU", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Gpu":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Memory:
    """Memory stores resource quantity and memory attributes."""
    # Quantity of memory available, which represents the amount of memory in bytes. This field is required and must be a non-negative integer.
    quantity: Optional[ResourceValue] = None
    # Attributes that describe the memory, such as its type and speed. This field is required and must be a list of Attribute key-values.
    attributes: List[Attribute] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.base.resources.v1beta4.Memory", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Memory":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Storage:
    """Storage stores resource quantity and storage attributes."""
    # Name holds an arbitrary name for the storage resource.
    name: str = ""
    # Quantity of storage available, which represents the amount of memory in bytes. This field is required and must be a non-negative integer.
    quantity: Optional[ResourceValue] = None
    # Attributes that describe the storage. This field is required and must be a list of Attribute key-values.
    attributes: List[Attribute] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.base.resources.v1beta4.Storage", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Storage":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Endpoint:
    """Endpoint describes a publicly accessible IP service."""
    # Kind describes how the endpoint is implemented when the lease is deployed.
    kind: int = 0
    # SequenceNumber represents a sequence number for the Endpoint.
    sequence_number: int = 0
    TYPE_URL: str = field(default="/akash.base.resources.v1beta4.Endpoint", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Endpoint":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Resources:
    """Resources describes all available resources types for deployment/node etc if field is nil resource is not present in the given data-structure"""
    # Id is a unique identifier for the resources.
    id: int = 0
    # CPU resources available, including the architecture, number of cores and other details. This field is optional and can be empty if no CPU resources are available.
    cpu: Optional[Cpu] = None
    # Memory resources available, including the quantity and attributes. This field is optional and can be empty if no memory resources are available.
    memory: Optional[Memory] = None
    # Storage resources available, including the quantity and attributes. This field is optional and can be empty if no storage resources are available.
    storage: List[Storage] = field(default_factory=list)
    # GPU resources available, including the type, architecture and other details. This field is optional and can be empty if no GPU resources are available.
    gpu: Optional[Gpu] = None
    # Endpoint resources available
    endpoints: List[Endpoint] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.base.resources.v1beta4.Resources", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Resources":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

