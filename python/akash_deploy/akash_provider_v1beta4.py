# Auto-generated from akash.provider.v1beta4 — do not edit.
# Source: terp-rs/proto/src/gen/akash.provider.v1beta4.rs
# Package: akash.provider.v1beta4
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.provider.v1beta4"

@dataclass
class Info:
    """Info contains information on the provider."""
    # Email is the email address to contact the provider.
    email: str = ""
    # Website is the URL to the landing page or socials of the provider.
    website: str = ""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.Info", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Info":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Provider:
    """Provider stores owner and host details. Akash providers are entities that contribute computing resources to the network. They can be individuals or organizations with underutilized computing resources, such as data centers or personal servers. Providers participate in the network by running the Akash node software and setting the price for their services. Users can then choose a provider based on factors such as cost, performance, and location."""
    # Owner is the bech32 address of the account of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # HostURI is the Uniform Resource Identifier for provider connection. This URI is used to directly connect to the provider to perform tasks such as sending the manifest.
    host_uri: str = ""
    # Attributes is a list of arbitrary attribute key-value pairs.
    attributes: List[Any] = field(default_factory=list)
    # Info contains additional provider information.
    info: Optional[Info] = None
    TYPE_URL: str = field(default="/akash.provider.v1beta4.Provider", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Provider":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryProvidersRequest:
    """QueryProvidersRequest is request type for the Query/Providers RPC method"""
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.provider.v1beta4.QueryProvidersRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryProvidersRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryProvidersResponse:
    """QueryProvidersResponse is response type for the Query/Providers RPC method"""
    # Providers is a list of providers on the network.
    providers: List[Provider] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.provider.v1beta4.QueryProvidersResponse", init=False, repr=False)

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
    # Owner is the bech32 address of the account of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.QueryProviderRequest", init=False, repr=False)

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
class QueryProviderResponse:
    """QueryProviderResponse is response type for the Query/Provider RPC method."""
    # Provider holds the representation of a provider on the network.
    provider: Optional[Provider] = None
    TYPE_URL: str = field(default="/akash.provider.v1beta4.QueryProviderResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryProviderResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventProviderCreated:
    """EventProviderCreated defines an SDK message for provider created event. It contains all the required information to identify a provider on-chain."""
    # Owner is the bech32 address of the account of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.EventProviderCreated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventProviderCreated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventProviderUpdated:
    """EventProviderUpdated defines an SDK message for provider updated event. It contains all the required information to identify a provider on-chain."""
    # Owner is the bech32 address of the account of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.EventProviderUpdated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventProviderUpdated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventProviderDeleted:
    """EventProviderDeleted defines an SDK message for provider deleted event."""
    # Owner is the bech32 address of the account of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.EventProviderDeleted", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventProviderDeleted":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateProvider:
    """MsgCreateProvider defines an SDK message for creating a provider."""
    # Owner is the bech32 address of the account of the provider. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # HostURI is the Uniform Resource Identifier for provider connection. This URI is used to directly connect to the provider to perform tasks such as sending the manifest.
    host_uri: str = ""
    # Attributes is a list of arbitrary attribute key-value pairs.
    attributes: List[Any] = field(default_factory=list)
    # Info contains additional provider information.
    info: Optional[Info] = None
    TYPE_URL: str = field(default="/akash.provider.v1beta4.MsgCreateProvider", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateProvider":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateProviderResponse:
    """MsgCreateProviderResponse defines the Msg/CreateProvider response type."""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.MsgCreateProviderResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateProviderResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateProvider:
    """MsgUpdateProvider defines an SDK message for updating a provider"""
    owner: str = ""
    host_uri: str = ""
    attributes: List[Any] = field(default_factory=list)
    info: Optional[Info] = None
    TYPE_URL: str = field(default="/akash.provider.v1beta4.MsgUpdateProvider", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgUpdateProvider":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateProviderResponse:
    """MsgUpdateProviderResponse defines the Msg/UpdateProvider response type."""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.MsgUpdateProviderResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgUpdateProviderResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgDeleteProvider:
    """MsgDeleteProvider defines an SDK message for deleting a provider"""
    owner: str = ""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.MsgDeleteProvider", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgDeleteProvider":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgDeleteProviderResponse:
    """MsgDeleteProviderResponse defines the Msg/DeleteProvider response type."""
    TYPE_URL: str = field(default="/akash.provider.v1beta4.MsgDeleteProviderResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgDeleteProviderResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the basic genesis state used by provider module."""
    # Providers is a list of genesis providers.
    providers: List[Provider] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.provider.v1beta4.GenesisState", init=False, repr=False)

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

