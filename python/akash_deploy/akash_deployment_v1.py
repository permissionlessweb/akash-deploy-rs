# Auto-generated from akash.deployment.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.deployment.v1.rs
# Package: akash.deployment.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.deployment.v1"

@dataclass
class GroupId:
    """GroupID uniquely identifies a group within a deployment on the network. A group represents a specific collection of resources or configurations within a deployment. It stores owner, deployment sequence number (dseq) and group sequence number (gseq)."""
    # Owner is the account address of the user who owns the group. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: int = 0
    TYPE_URL: str = field(default="/akash.deployment.v1.GroupID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GroupId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class DeploymentId:
    """DeploymentID represents a unique identifier for a specific deployment on the network. It is composed of two fields: an owner address and a sequence number (dseq)."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    TYPE_URL: str = field(default="/akash.deployment.v1.DeploymentID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "DeploymentId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Deployment:
    """Deployment stores deploymentID, state and checksum details."""
    # ID is the unique identifier of the deployment.
    id: Optional[DeploymentId] = None
    # State defines the sate of the deployment. A deployment can be either active or inactive.
    state: int = 0
    # Hash is an hashed representation of the deployment.
    hash: str = ""
    # CreatedAt indicates when the deployment was created as a block height value.
    created_at: str = "0"
    TYPE_URL: str = field(default="/akash.deployment.v1.Deployment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Deployment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventDeploymentCreated:
    """EventDeploymentCreated event is triggered when deployment is created on chain. It contains all the information required to identify a deployment."""
    # ID is the unique identifier of the deployment.
    id: Optional[DeploymentId] = None
    # Hash is an hashed representation of the deployment.
    hash: str = ""
    TYPE_URL: str = field(default="/akash.deployment.v1.EventDeploymentCreated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventDeploymentCreated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventDeploymentUpdated:
    """EventDeploymentUpdated is triggered when deployment is updated on chain. It contains all the information required to identify a deployment."""
    # ID is the unique identifier of the deployment.
    id: Optional[DeploymentId] = None
    # Hash is an hashed representation of the deployment.
    hash: str = ""
    TYPE_URL: str = field(default="/akash.deployment.v1.EventDeploymentUpdated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventDeploymentUpdated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventDeploymentClosed:
    """EventDeploymentClosed is triggered when deployment is closed on chain. It contains all the information required to identify a deployment."""
    # ID is the unique identifier of the deployment.
    id: Optional[DeploymentId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1.EventDeploymentClosed", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventDeploymentClosed":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventGroupStarted:
    """EventGroupStarted is triggered when deployment group is started. It contains all the information required to identify a group."""
    # ID is the unique identifier of the group.
    id: Optional[GroupId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1.EventGroupStarted", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventGroupStarted":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventGroupPaused:
    """EventGroupPaused is triggered when deployment group is paused. It contains all the information required to identify a group."""
    # ID is the unique identifier of the group.
    id: Optional[GroupId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1.EventGroupPaused", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventGroupPaused":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventGroupClosed:
    """EventGroupClosed is triggered when deployment group is closed. It contains all the information required to identify a group."""
    # ID is the unique identifier of the group.
    id: Optional[GroupId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1.EventGroupClosed", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventGroupClosed":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

