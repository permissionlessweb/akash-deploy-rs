# Auto-generated from akash.market.v2beta1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.market.v2beta1.rs
# Package: akash.market.v2beta1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.market.v2beta1"

@dataclass
class ResourceOffer:
    """ResourceOffer describes resources that provider is offering for deployment."""
    # Resources holds information about bid resources.
    resources: Optional[Any  # Any] = None
    # Count is the number of resources.
    count: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.ResourceOffer", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "ResourceOffer":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class BidId:
    """BidID stores owner and all other seq numbers. A successful bid becomes a Lease(ID)."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: int = 0
    # Oseq (order sequence) distinguishes multiple orders associated with a single deployment. Oseq is incremented when a lease associated with an existing deployment is closed, and a new order is generated.
    oseq: int = 0
    # Provider is the account bech32 address of the provider making the bid. It is a string representing a valid account bech32 address.  Example: "akash1..."
    provider: str = ""
    # BSeq (bid sequence) distinguishes multiple bids associated with a single deployment from same provider.
    bseq: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.BidID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "BidId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Bid:
    """Bid stores BidID, state of bid and price."""
    # BidID stores owner and all other seq numbers. A successful bid becomes a Lease(ID).
    id: Optional[BidId] = None
    # State represents the state of the Bid.
    state: int = 0
    # Price holds the pricing stated on the Bid.
    prices: List[Any] = field(default_factory=list)
    # CreatedAt is the block height at which the Bid was created.
    created_at: str = "0"
    # ResourceOffer is a list of offers.
    resources_offer: List[ResourceOffer] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.market.v2beta1.Bid", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Bid":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class LeaseId:
    """LeaseID stores bid details of lease."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: int = 0
    # Oseq (order sequence) distinguishes multiple orders associated with a single deployment. Oseq is incremented when a lease associated with an existing deployment is closed, and a new order is generated.
    oseq: int = 0
    # Provider is the account bech32 address of the provider making the bid. It is a string representing a valid account bech32 address.  Example: "akash1..."
    provider: str = ""
    # BSeq (bid sequence) distinguishes multiple bids associated with a single deployment from same provider.
    bseq: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.LeaseID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "LeaseId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Lease:
    """Lease stores LeaseID, state of lease and price. The Lease defines the terms under which the provider allocates resources to fulfill the tenant's deployment requirements. Leases are paid from the tenant to the provider through a deposit and withdraw mechanism and are priced in blocks."""
    # Id is the unique identifier of the Lease.
    id: Optional[LeaseId] = None
    # State represents the state of the Lease.
    state: int = 0
    # Price holds the settled price for the Lease.
    prices: List[Any] = field(default_factory=list)
    # CreatedAt is the block height at which the Lease was created.
    created_at: str = "0"
    # ClosedOn is the block height at which the Lease was closed.
    closed_on: str = "0"
    reason: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.Lease", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Lease":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateLease:
    """MsgCreateLease is sent to create a lease."""
    # BidId is the unique identifier of the Bid.
    bid_id: Optional[BidId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCreateLease", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateLease":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateLeaseResponse:
    """MsgCreateLeaseResponse is the response from creating a lease."""
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCreateLeaseResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateLeaseResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgWithdrawLease:
    """MsgWithdrawLease defines an SDK message for withdrawing lease funds."""
    # BidId is the unique identifier of the Bid.
    id: Optional[LeaseId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgWithdrawLease", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgWithdrawLease":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgWithdrawLeaseResponse:
    """MsgWithdrawLeaseResponse defines the Msg/WithdrawLease response type."""
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgWithdrawLeaseResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgWithdrawLeaseResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseLease:
    """MsgCloseLease defines an SDK message for closing order."""
    # LeaseID is the unique identifier of the Lease.
    id: Optional[LeaseId] = None
    reason: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCloseLease", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseLease":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseLeaseResponse:
    """MsgCloseLeaseResponse defines the Msg/CloseLease response type."""
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCloseLeaseResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseLeaseResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Params:
    """Params is the params for the x/market module."""
    # BidMinDeposit is a parameter for the minimum deposit on a Bid.
    bid_min_deposit: Optional[Any  # Any] = None
    # OrderMaxBids is a parameter for the maximum number of bids in an order.
    order_max_bids: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.Params", init=False, repr=False)

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
    # authority is the address of the governance account.
    authority: str = ""
    # params defines the x/deployment parameters to update.  NOTE: All parameters must be supplied.
    params: Optional[Params] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgUpdateParams", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgUpdateParamsResponse", init=False, repr=False)

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
class MsgCreateBid:
    """MsgCreateBid defines an SDK message for creating Bid."""
    id: Optional[BidId] = None
    # Prices holds the pricing options stated on the Bid.
    prices: List[Any] = field(default_factory=list)
    # Deposit holds the amount of coins to deposit.
    deposit: Optional[Any  # Deposit] = None
    # ResourceOffer is a list of resource offers.
    resources_offer: List[ResourceOffer] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCreateBid", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateBid":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateBidResponse:
    """MsgCreateBidResponse defines the Msg/CreateBid response type."""
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCreateBidResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateBidResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseBid:
    """MsgCloseBid defines an SDK message for closing bid."""
    # Id is the unique identifier of the Bid.
    id: Optional[BidId] = None
    reason: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCloseBid", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseBid":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCloseBidResponse:
    """MsgCloseBidResponse defines the Msg/CloseBid response type."""
    TYPE_URL: str = field(default="/akash.market.v2beta1.MsgCloseBidResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCloseBidResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class LeaseFilters:
    """LeaseFilters defines flags for lease list filtering."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: int = 0
    # Oseq (order sequence) distinguishes multiple orders associated with a single deployment. Oseq is incremented when a lease associated with an existing deployment is closed, and a new order is generated.
    oseq: int = 0
    # Provider is the account bech32 address of the provider making the bid. It is a string representing a valid account bech32 address.  Example: "akash1..."
    provider: str = ""
    # State represents the state of the lease.
    state: str = ""
    # BSeq (bid sequence) distinguishes multiple bids associated with a single deployment from same provider.
    bseq: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.LeaseFilters", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "LeaseFilters":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class BidFilters:
    """BidFilters defines flags for bid list filter."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: int = 0
    # Oseq (order sequence) distinguishes multiple orders associated with a single deployment. Oseq is incremented when a lease associated with an existing deployment is closed, and a new order is generated.
    oseq: int = 0
    # Provider is the account bech32 address of the provider making the bid. It is a string representing a valid account bech32 address.  Example: "akash1..."
    provider: str = ""
    # State represents the state of the lease.
    state: str = ""
    # BSeq (bid sequence) distinguishes multiple bids associated with a single deployment from same provider.
    bseq: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.BidFilters", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "BidFilters":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class OrderFilters:
    """OrderFilters defines flags for order list filter"""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: int = 0
    # Oseq (order sequence) distinguishes multiple orders associated with a single deployment. Oseq is incremented when a lease associated with an existing deployment is closed, and a new order is generated.
    oseq: int = 0
    # State represents the state of the lease.
    state: str = ""
    TYPE_URL: str = field(default="/akash.market.v2beta1.OrderFilters", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "OrderFilters":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class OrderId:
    """OrderId stores owner and all other seq numbers."""
    # Owner is the account bech32 address of the user who owns the deployment. It is a string representing a valid bech32 account address.  Example: "akash1..."
    owner: str = ""
    # Dseq (deployment sequence number) is a unique numeric identifier for the deployment. It is used to differentiate deployments created by the same owner.
    dseq: str = "0"
    # Gseq (group sequence number) is a unique numeric identifier for the group. It is used to differentiate groups created by the same owner in a deployment.
    gseq: int = 0
    # Oseq (order sequence) distinguishes multiple orders associated with a single deployment. Oseq is incremented when a lease associated with an existing deployment is closed, and a new order is generated.
    oseq: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.OrderID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "OrderId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Order:
    """Order stores orderID, state of order and other details."""
    # Id is the unique identifier of the order.
    id: Optional[OrderId] = None
    state: int = 0
    spec: Optional[Any  # GroupSpec] = None
    created_at: str = "0"
    TYPE_URL: str = field(default="/akash.market.v2beta1.Order", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Order":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryOrdersRequest:
    """QueryOrdersRequest is request type for the Query/Orders RPC method."""
    # Filters holds the fields to filter orders.
    filters: Optional[OrderFilters] = None
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryOrdersRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryOrdersRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryOrdersResponse:
    """QueryOrdersResponse is response type for the Query/Orders RPC method"""
    # Orders is a list of market orders.
    orders: List[Order] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryOrdersResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryOrdersResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryOrderRequest:
    """QueryOrderRequest is request type for the Query/Order RPC method."""
    # Id is the unique identifier of the Order.
    id: Optional[OrderId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryOrderRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryOrderRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryOrderResponse:
    """QueryOrderResponse is response type for the Query/Order RPC method."""
    # Order represents a market order.
    order: Optional[Order] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryOrderResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryOrderResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryBidsRequest:
    """QueryBidsRequest is request type for the Query/Bids RPC method."""
    # Filters holds the fields to filter bids.
    filters: Optional[BidFilters] = None
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryBidsRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryBidsRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryBidsResponse:
    """QueryBidsResponse is response type for the Query/Bids RPC method"""
    # Bids is a list of deployment bids.
    bids: List[QueryBidResponse] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryBidsResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryBidsResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryBidRequest:
    """QueryBidRequest is request type for the Query/Bid RPC method."""
    # Id is the unique identifier for the Bid.
    id: Optional[BidId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryBidRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryBidRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryBidResponse:
    """QueryBidResponse is response type for the Query/Bid RPC method."""
    # Bid represents a deployment bid.
    bid: Optional[Bid] = None
    # EscrowAccount represents the escrow account created for the Bid.
    escrow_account: Optional[Any  # Account] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryBidResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryBidResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryLeasesRequest:
    """QueryLeasesRequest is request type for the Query/Leases RPC method."""
    # Filters holds the fields to filter leases.
    filters: Optional[LeaseFilters] = None
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryLeasesRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryLeasesRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryLeasesResponse:
    """QueryLeasesResponse is response type for the Query/Leases RPC method."""
    # Leases is a list of Lease.
    leases: List[QueryLeaseResponse] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryLeasesResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryLeasesResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryLeaseRequest:
    """QueryLeaseRequest is request type for the Query/Lease RPC method."""
    # Id is the unique identifier of the Lease.
    id: Optional[LeaseId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryLeaseRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryLeaseRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryLeaseResponse:
    """QueryLeaseResponse is response type for the Query/Lease RPC method"""
    # Lease holds the lease for a deployment.
    lease: Optional[Lease] = None
    # EscrowPayment holds information about the Lease's fractional payment.
    escrow_payment: Optional[Any  # Payment] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryLeaseResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryLeaseResponse":
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
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryParamsRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v2beta1.QueryParamsResponse", init=False, repr=False)

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
class EventOrderCreated:
    """EventOrderCreated is triggered when an order is created. It contains all the information required to identify an order."""
    # Id is the unique identifier of the Order.
    id: Optional[OrderId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.EventOrderCreated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventOrderCreated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventOrderClosed:
    """EventOrderClosed is triggered when an order is closed. It contains all the information required to identify an order."""
    # Id is the unique identifier of the Order.
    id: Optional[OrderId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.EventOrderClosed", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventOrderClosed":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventBidCreated:
    """EventBidCreated is triggered when a bid is created. It contains all the information required to identify a bid."""
    # Id is the unique identifier of the Bid.
    id: Optional[BidId] = None
    # Price stated on the Bid.
    prices: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.market.v2beta1.EventBidCreated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventBidCreated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventBidClosed:
    """EventBidClosed is triggered when a bid is closed. It contains all the information required to identify a bid."""
    # Id is the unique identifier of the Bid.
    id: Optional[BidId] = None
    TYPE_URL: str = field(default="/akash.market.v2beta1.EventBidClosed", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventBidClosed":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventLeaseCreated:
    """EventLeaseCreated is triggered when a lease is created. It contains all the information required to identify a lease."""
    # Id is the unique identifier of the Lease.
    id: Optional[LeaseId] = None
    # Price settled for the lease.
    prices: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.market.v2beta1.EventLeaseCreated", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventLeaseCreated":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventLeaseClosed:
    """EventLeaseClosed is triggered when a lease is closed. It contains all the information required to identify a lease."""
    # Id is the unique identifier of the Lease.
    id: Optional[LeaseId] = None
    reason: int = 0
    TYPE_URL: str = field(default="/akash.market.v2beta1.EventLeaseClosed", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventLeaseClosed":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the basic genesis state used by market module."""
    # Params holds parameters of the genesis of market.
    params: Optional[Params] = None
    # Orders is a list of orders in the genesis state.
    orders: List[Order] = field(default_factory=list)
    # Leases is a list of leases in the genesis state.
    leases: List[Lease] = field(default_factory=list)
    # Bids is a list of bids in the genesis state.
    bids: List[Bid] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.market.v2beta1.GenesisState", init=False, repr=False)

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

