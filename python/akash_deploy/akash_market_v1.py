# Auto-generated from akash.market.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.market.v1.rs
# Package: akash.market.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.market.v1"

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
    TYPE_URL: str = field(default="/akash.market.v1.BidID", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1.LeaseFilters", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1.OrderID", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1.LeaseID", init=False, repr=False)

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
    price: Optional[Any  # Any] = None
    # CreatedAt is the block height at which the Lease was created.
    created_at: str = "0"
    # ClosedOn is the block height at which the Lease was closed.
    closed_on: str = "0"
    reason: int = 0
    TYPE_URL: str = field(default="/akash.market.v1.Lease", init=False, repr=False)

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
class EventOrderCreated:
    """EventOrderCreated is triggered when an order is created. It contains all the information required to identify an order."""
    # Id is the unique identifier of the Order.
    id: Optional[OrderId] = None
    TYPE_URL: str = field(default="/akash.market.v1.EventOrderCreated", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1.EventOrderClosed", init=False, repr=False)

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
    price: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v1.EventBidCreated", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1.EventBidClosed", init=False, repr=False)

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
    price: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.market.v1.EventLeaseCreated", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.market.v1.EventLeaseClosed", init=False, repr=False)

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

