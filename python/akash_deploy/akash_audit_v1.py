# Auto-generated from akash.audit.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.audit.v1.rs
# Package: akash.audit.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.audit.v1"

@dataclass
class AuditedProvider:
    """AuditedProvider stores owner, auditor and attributes details. An AuditedProvider is a provider that has undergone a verification or auditing process to ensure that it meets certain standards or requirements by an auditor. An auditor can be any valid account on-chain. NOTE: There are certain teams providing auditing services, which should be accounted for when deploying."""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Auditor is the account bech32 address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    # Attributes holds a list of key-value pairs of provider attributes. Attributes are arbitrary values that a provider exposes.
    attributes: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.audit.v1.AuditedProvider", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "AuditedProvider":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class AuditedAttributesStore:
    """AuditedAttributesStore stores the audited attributes of the provider. Attributes that have been audited are those that have been verified by an auditor."""
    # Attributes holds a list of key-value pairs of provider attributes. Attributes are arbitrary values that a provider exposes.
    attributes: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.audit.v1.AuditedAttributesStore", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "AuditedAttributesStore":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class AttributesFilters:
    """AttributesFilters defines attribute filters that can be used to filter deployments."""
    # Auditors contains a list of auditor account bech32 addresses.
    auditors: List[str] = field(default_factory=list)
    # Owners contains a list of owner account bech32 addresses.
    owners: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.audit.v1.AttributesFilters", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "AttributesFilters":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryProvidersResponse:
    """QueryProvidersResponse is response type for the Query/Providers RPC method."""
    # Providers contains a list of audited providers account addresses.
    providers: List[AuditedProvider] = field(default_factory=list)
    # Pagination is used to paginate results.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.audit.v1.QueryProvidersResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryProvidersResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryProviderRequest:
    """QueryProviderRequest is request type for the Query/Provider RPC method"""
    # Auditor is the account address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    TYPE_URL: str = field(default="/akash.audit.v1.QueryProviderRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryProviderRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryAllProvidersAttributesRequest:
    """QueryAllProvidersAttributesRequest is request type for the Query/All Providers RPC method."""
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.audit.v1.QueryAllProvidersAttributesRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryAllProvidersAttributesRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryProviderAttributesRequest:
    """QueryProviderAttributesRequest is request type for the Query/Provider RPC method."""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.audit.v1.QueryProviderAttributesRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryProviderAttributesRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryProviderAuditorRequest:
    """QueryProviderAuditorRequest is request type for the Query/Providers RPC method."""
    # Auditor is the account address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    TYPE_URL: str = field(default="/akash.audit.v1.QueryProviderAuditorRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryProviderAuditorRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryAuditorAttributesRequest:
    """QueryAuditorAttributesRequest is request type for the Query/Providers RPC method."""
    # Auditor is the account address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.audit.v1.QueryAuditorAttributesRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryAuditorAttributesRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventTrustedAuditorCreated:
    """EventTrustedAuditorCreated defines an SDK message for when a trusted auditor is created."""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Auditor is the account address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    TYPE_URL: str = field(default="/akash.audit.v1.EventTrustedAuditorCreated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventTrustedAuditorCreated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventTrustedAuditorDeleted:
    """EventTrustedAuditorDeleted defines an event for when a trusted auditor is deleted."""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Auditor is the account address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    TYPE_URL: str = field(default="/akash.audit.v1.EventTrustedAuditorDeleted", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventTrustedAuditorDeleted":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgSignProviderAttributes:
    """MsgSignProviderAttributes defines an SDK message for signing a provider attributes."""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Auditor is the account address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    # Attributes holds a list of key-value pairs of provider attributes to be audited. Attributes are arbitrary values that a provider exposes.
    attributes: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.audit.v1.MsgSignProviderAttributes", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgSignProviderAttributes":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgSignProviderAttributesResponse:
    """MsgSignProviderAttributesResponse defines the Msg/CreateProvider response type."""
    TYPE_URL: str = field(default="/akash.audit.v1.MsgSignProviderAttributesResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgSignProviderAttributesResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgDeleteProviderAttributes:
    """MsgDeleteProviderAttributes defined the Msg/DeleteProviderAttributes"""
    # Owner is the account bech32 address of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Auditor is the account address of the auditor. It is a string representing a valid account address.  Example: "akash1..."
    auditor: str = ""
    # Keys holds a list of keys of audited provider attributes to delete from the audit.
    keys: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.audit.v1.MsgDeleteProviderAttributes", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgDeleteProviderAttributes":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgDeleteProviderAttributesResponse:
    """MsgDeleteProviderAttributesResponse defines the Msg/ProviderAttributes response type."""
    TYPE_URL: str = field(default="/akash.audit.v1.MsgDeleteProviderAttributesResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgDeleteProviderAttributesResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the basic genesis state used by audit module."""
    # Providers contains a list of audited providers account addresses.
    providers: List[AuditedProvider] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.audit.v1.GenesisState", init=False, repr=False)

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

