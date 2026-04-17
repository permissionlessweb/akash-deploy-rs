# Auto-generated from akash.market.v1beta5 — do not edit.
# Source: terp-rs/proto/src/gen/akash.market.v1beta5.rs
# Package: akash.market.v1beta5
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.market.v1beta5"

@dataclass
class MsgCreateLease:
    """MsgCreateLease is sent to create a lease."""
    # BidId is the unique identifier of the Bid.
    bid_id: Optional[Any  # BidId] = None
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCreateLease", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCreateLeaseResponse", init=False, repr=False)

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
    id: Optional[Any  # LeaseId] = None
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgWithdrawLease", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgWithdrawLeaseResponse", init=False, repr=False)

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
    id: Optional[Any  # LeaseId] = None
    reason: int = 0
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCloseLease", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCloseLeaseResponse", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.Params", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgUpdateParams", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgUpdateParamsResponse", init=False, repr=False)

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
class ResourceOffer:
    """ResourceOffer describes resources that provider is offering for deployment."""
    # Resources holds information about bid resources.
    resources: Optional[Any  # Any] = None
    # Count is the number of resources.
    count: int = 0
    TYPE_URL: str = field(default="/akash.market.v1beta5.ResourceOffer", init=False, repr=False)

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
class MsgCreateBid:
    """MsgCreateBid defines an SDK message for creating Bid."""
    id: Optional[Any  # BidId] = None
    # Price holds the pricing stated on the Bid.
    price: Optional[Any  # Any] = None
    # Deposit holds the amount of coins to deposit.
    deposit: Optional[Any  # Deposit] = None
    # ResourceOffer is a list of resource offers.
    resources_offer: List[ResourceOffer] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCreateBid", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCreateBidResponse", init=False, repr=False)

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
    id: Optional[Any  # BidId] = None
    reason: int = 0
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCloseBid", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.MsgCloseBidResponse", init=False, repr=False)

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
class Bid:
    """Bid stores BidID, state of bid and price."""
    # BidID stores owner and all other seq numbers. A successful bid becomes a Lease(ID).
    id: Optional[Any  # BidId] = None
    # State represents the state of the Bid.
    state: int = 0
    # Price holds the pricing stated on the Bid.
    price: Optional[Any  # Any] = None
    # CreatedAt is the block height at which the Bid was created.
    created_at: str = "0"
    # ResourceOffer is a list of offers.
    resources_offer: List[ResourceOffer] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.market.v1beta5.Bid", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.BidFilters", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.OrderFilters", init=False, repr=False)

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
class Order:
    """Order stores orderID, state of order and other details."""
    # Id is the unique identifier of the order.
    id: Optional[Any  # OrderId] = None
    state: int = 0
    spec: Optional[Any  # GroupSpec] = None
    created_at: str = "0"
    TYPE_URL: str = field(default="/akash.market.v1beta5.Order", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryOrdersRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryOrdersResponse", init=False, repr=False)

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
    id: Optional[Any  # OrderId] = None
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryOrderRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryOrderResponse", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryBidsRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryBidsResponse", init=False, repr=False)

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
    id: Optional[Any  # BidId] = None
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryBidRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryBidResponse", init=False, repr=False)

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
    filters: Optional[Any  # LeaseFilters] = None
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryLeasesRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryLeasesResponse", init=False, repr=False)

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
    id: Optional[Any  # LeaseId] = None
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryLeaseRequest", init=False, repr=False)

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
    lease: Optional[Any  # Lease] = None
    # EscrowPayment holds information about the Lease's fractional payment.
    escrow_payment: Optional[Any  # Payment] = None
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryLeaseResponse", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryParamsRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.QueryParamsResponse", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1beta5.GenesisState", init=False, repr=False)

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

