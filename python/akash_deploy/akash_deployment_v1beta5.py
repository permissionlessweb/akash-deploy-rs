# Auto-generated from akash.deployment.v1beta5 — do not edit.
# Source: terp-rs/proto/src/gen/akash.deployment.v1beta5.rs
# Package: akash.deployment.v1beta5
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.deployment.v1beta5"

@dataclass
class Params:
    """Params defines the parameters for the x/deployment module."""
    # MinDeposits holds a list of the minimum amount of deposits for each a coin.
    min_deposits: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.Params", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Params":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateParams:
    """MsgUpdateParams is the Msg/UpdateParams request type.  Since: akash v1.0.0"""
    # Authority is the address of the governance account.
    authority: str = ""
    # Params defines the x/deployment parameters to update.  NOTE: All parameters must be supplied.
    params: Optional[Params] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgUpdateParams", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgUpdateParams":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateParamsResponse:
    """MsgUpdateParamsResponse defines the response structure for executing a MsgUpdateParams message.  Since: akash v1.0.0"""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgUpdateParamsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgUpdateParamsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseGroup:
    """MsgCloseGroup defines SDK message to close a single Group within a Deployment."""
    # Id is the unique identifier of the Group.
    id: Optional[Any  # GroupId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgCloseGroup", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseGroup":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseGroupResponse:
    """MsgCloseGroupResponse defines the Msg/CloseGroup response type."""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgCloseGroupResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseGroupResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgPauseGroup:
    """MsgPauseGroup defines SDK message to pause a single Group within a Deployment."""
    # Id is the unique identifier of the Group.
    id: Optional[Any  # GroupId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgPauseGroup", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgPauseGroup":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgPauseGroupResponse:
    """MsgPauseGroupResponse defines the Msg/PauseGroup response type."""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgPauseGroupResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgPauseGroupResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgStartGroup:
    """MsgStartGroup defines SDK message to start a single Group within a Deployment."""
    # Id is the unique identifier of the Group.
    id: Optional[Any  # GroupId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgStartGroup", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgStartGroup":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgStartGroupResponse:
    """MsgStartGroupResponse defines the Msg/StartGroup response type."""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgStartGroupResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgStartGroupResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class ResourceUnit:
    """ResourceUnit extends Resources and adds Count along with the Price."""
    # Resource holds the amount of resources.
    resource: Optional[Any  # Any] = None
    # Count corresponds to the amount of replicas to run of the resources.
    count: int = 0
    # Price holds the pricing for the resource units.
    prices: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.ResourceUnit", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ResourceUnit":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GroupSpec:
    """GroupSpec defines a specification for a group in a deployment on the network. This includes attributes like the group name, placement requirements, and resource units."""
    # Name is the name of the group.
    name: str = ""
    # Requirements specifies the placement requirements for the group. This determines where the resources in the group can be deployed.
    requirements: Optional[Any  # Any] = None
    # Resources is a list containing the resource units allocated to the group. Each ResourceUnit defines the specific resources (e.g., CPU, memory) assigned.
    resources: List[ResourceUnit] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.GroupSpec", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GroupSpec":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Group:
    """Group stores group id, state and specifications of a group."""
    # Id is the unique identifier for the group.
    id: Optional[Any  # GroupId] = None
    # State represents the state of the group.
    state: int = 0
    # GroupSpec holds the specification of a the Group.
    group_spec: Optional[GroupSpec] = None
    # CreatedAt is the block height at which the deployment was created.
    created_at: str = "0"
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.Group", init=False, repr=False)

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

@dataclass
class DeploymentFilters:
    """DeploymentFilters defines filters used to filter deployments."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # State defines the sate of the deployment. A deployment can be either active or inactive.
    state: str = ""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.DeploymentFilters", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "DeploymentFilters":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GroupFilters:
    """GroupFilters defines filters used to filter groups"""
    # Owner is the account address of the user who owns the group. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: str = "0"
    # State defines the sate of the deployment. A deployment can be either active or inactive.
    state: str = ""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.GroupFilters", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GroupFilters":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryDeploymentsRequest:
    """QueryDeploymentsRequest is request type for the Query/Deployments RPC method."""
    # Filters holds the deployment fields to filter the request.
    filters: Optional[DeploymentFilters] = None
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryDeploymentsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryDeploymentsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryDeploymentsResponse:
    """QueryDeploymentsResponse is response type for the Query/Deployments RPC method"""
    # Deployments is a list of Deployments.
    deployments: List[QueryDeploymentResponse] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryDeploymentsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryDeploymentsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryDeploymentRequest:
    """QueryDeploymentRequest is request type for the Query/Deployment RPC method."""
    # Id is the unique identifier of the deployment.
    id: Optional[Any  # DeploymentId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryDeploymentRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryDeploymentRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryDeploymentResponse:
    """QueryDeploymentResponse is response type for the Query/Deployment RPC method"""
    # Deployment represents a deployment on the network.
    deployment: Optional[Any  # Deployment] = None
    # Groups is a list of deployment groups.
    groups: List[Group] = field(default_factory=list)
    # EscrowAccount represents an escrow mechanism where funds are held. This ensures that obligations of both tenants and providers involved in the transaction are met without direct access to each other's accounts.
    escrow_account: Optional[Any  # Account] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryDeploymentResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryDeploymentResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryGroupRequest:
    """QueryGroupRequest is request type for the Query/Group RPC method."""
    # Id is the unique identifier of the Group.
    id: Optional[Any  # GroupId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryGroupRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryGroupRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryGroupResponse:
    """QueryGroupResponse is response type for the Query/Group RPC method."""
    # Group holds a deployment Group.
    group: Optional[Group] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryGroupResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryGroupResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryParamsRequest:
    """QueryParamsRequest is the request type for the Query/Params RPC method."""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryParamsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryParamsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryParamsResponse:
    """QueryParamsResponse is the response type for the Query/Params RPC method."""
    # params defines the parameters of the module.
    params: Optional[Params] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.QueryParamsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryParamsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateDeployment:
    """MsgCreateDeployment defines an SDK message for creating deployment."""
    # ID is the unique identifier of the deployment.
    id: Optional[Any  # DeploymentId] = None
    # GroupSpec is a list of group specifications for the deployment. This field is required and must be a list of GroupSpec.
    groups: List[GroupSpec] = field(default_factory=list)
    # Hash of the deployment.
    hash: str = ""
    # Deposit specifies the amount of coins to include in the deployment's first deposit.
    deposits: List[Deposit] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgCreateDeployment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateDeployment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateDeploymentResponse:
    """MsgCreateDeploymentResponse defines the Msg/CreateDeployment response type."""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgCreateDeploymentResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateDeploymentResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateDeployment:
    """MsgUpdateDeployment defines an SDK message for updating deployment."""
    # ID is the unique identifier of the deployment.
    id: Optional[Any  # DeploymentId] = None
    # Hash of the deployment.
    hash: str = ""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgUpdateDeployment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgUpdateDeployment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateDeploymentResponse:
    """MsgUpdateDeploymentResponse defines the Msg/UpdateDeployment response type."""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgUpdateDeploymentResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgUpdateDeploymentResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseDeployment:
    """MsgCloseDeployment defines an SDK message for closing deployment"""
    # ID is the unique identifier of the deployment.
    id: Optional[Any  # DeploymentId] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgCloseDeployment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseDeployment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseDeploymentResponse:
    """MsgCloseDeploymentResponse defines the Msg/CloseDeployment response type."""
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.MsgCloseDeploymentResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseDeploymentResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisDeployment:
    """GenesisDeployment defines the basic genesis state used by deployment module."""
    # Deployments represents a deployment on the network.
    deployment: Optional[Any  # Deployment] = None
    # Groups is a list of groups within a Deployment.
    groups: List[Group] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.GenesisDeployment", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisDeployment":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState stores slice of genesis deployment instance."""
    # Deployments is a list of deployments on the network.
    deployments: List[GenesisDeployment] = field(default_factory=list)
    # Params defines the parameters for the x/deployment module.
    params: Optional[Params] = None
    TYPE_URL: str = field(default="/akash.deployment.v1beta5.GenesisState", init=False, repr=False)

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

