# Auto-generated from akash.base.attributes.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.base.attributes.v1.rs
# Package: akash.base.attributes.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.base.attributes.v1"

@dataclass
class Attribute:
    """Attribute represents an arbitrary attribute key-value pair."""
    # Key of the attribute (e.g., "region", "cpu_architecture", etc.).
    key: str = ""
    # Value of the attribute (e.g., "us-west", "x86_64", etc.).
    value: str = ""
    TYPE_URL: str = field(default="/akash.base.attributes.v1.Attribute", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Attribute":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class SignedBy:
    """SignedBy represents validation accounts that tenant expects signatures for provider attributes. AllOf has precedence i.e. if there is at least one entry AnyOf is ignored regardless to how many entries there.  TODO: this behaviour to be discussed"""
    # AllOf indicates all keys in this list must have signed attributes.
    all_of: List[str] = field(default_factory=list)
    # AnyOf means that at least one of the keys from the list must have signed attributes.
    any_of: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.base.attributes.v1.SignedBy", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "SignedBy":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PlacementRequirements:
    """PlacementRequirements represents the requirements for a provider placement on the network. It is used to specify the characteristics and constraints of a provider that can be used to satisfy a deployment request."""
    # SignedBy holds the list of keys that tenants expect to have signatures from.
    signed_by: Optional[SignedBy] = None
    # Attribute holds the list of attributes tenant expects from the provider.
    attributes: List[Attribute] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.base.attributes.v1.PlacementRequirements", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PlacementRequirements":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

