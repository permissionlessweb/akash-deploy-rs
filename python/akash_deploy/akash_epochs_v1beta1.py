# Auto-generated from akash.epochs.v1beta1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.epochs.v1beta1.rs
# Package: akash.epochs.v1beta1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.epochs.v1beta1"

@dataclass
class EventEpochEnd:
    """EventEpochEnd is an event emitted when an epoch end."""
    epoch_number: str = "0"
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.EventEpochEnd", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventEpochEnd":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventEpochStart:
    """EventEpochStart is an event emitted when an epoch start."""
    epoch_number: str = "0"
    epoch_start_time: str = "0"
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.EventEpochStart", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventEpochStart":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EpochInfo:
    """EpochInfo is a struct that describes the data going into a timer defined by the x/epochs module."""
    # id is a unique reference to this particular timer.
    id: str = ""
    # start_time is the time at which the timer first ever ticks. If start_time is in the future, the epoch will not begin until the start time.
    start_time: Optional[Any  # Timestamp] = None
    # duration is the time in between epoch ticks. In order for intended behavior to be met, duration should be greater than the chains expected block time. Duration must be non-zero.
    duration: Optional[Any  # Duration] = None
    # current_epoch is the current epoch number, or in other words, how many times has the timer 'ticked'. The first tick (current_epoch=1) is defined as the first block whose blocktime is greater than the EpochInfo start_time.
    current_epoch: str = "0"
    # current_epoch_start_time describes the start time of the current timer interval. The interval is (current_epoch_start_time, current_epoch_start_time + duration\] When the timer ticks, this is set to current_epoch_start_time = last_epoch_start_time + duration only one timer tick for a given identifier can occur per block.  NOTE! The current_epoch_start_time may diverge significantly from the wall-clock time the epoch began at. Wall-clock time of epoch start may be  > >  > >  > current_epoch_start_time. Suppose current_epoch_start_time = 10, >  > duration = 5. Suppose the chain goes offline at t=14, and comes back online >  > at t=30, and produces blocks at every successive time. (t=31, 32, etc.)  * The t=30 block will start the epoch for (10, 15\] * The t=31 block will start the epoch for (15, 20\] * The t=32 block will start the epoch for (20, 25\] * The t=33 block will start the epoch for (25, 30\] * The t=34 block will start the epoch for (30, 35\] * The **t=36** block will start the epoch for (35, 40\]
    current_epoch_start_time: Optional[Any  # Timestamp] = None
    # epoch_counting_started is a boolean, that indicates whether this epoch timer has began yet.
    epoch_counting_started: bool = False
    # current_epoch_start_height is the block height at which the current epoch started. (The block height at which the timer last ticked)
    current_epoch_start_height: str = "0"
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.EpochInfo", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EpochInfo":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the epochs module's genesis state."""
    epochs: List[EpochInfo] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.GenesisState", init=False, repr=False)

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

@dataclass
class QueryEpochInfosRequest:
    """QueryEpochInfosRequest defines the gRPC request structure for querying all epoch info."""
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.QueryEpochInfosRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryEpochInfosRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryEpochInfosResponse:
    """QueryEpochInfosRequest defines the gRPC response structure for querying all epoch info."""
    epochs: List[EpochInfo] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.QueryEpochInfosResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryEpochInfosResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryCurrentEpochRequest:
    """QueryCurrentEpochRequest defines the gRPC request structure for querying an epoch by its identifier."""
    identifier: str = ""
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.QueryCurrentEpochRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryCurrentEpochRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryCurrentEpochResponse:
    """QueryCurrentEpochResponse defines the gRPC response structure for querying an epoch by its identifier."""
    current_epoch: str = "0"
    TYPE_URL: str = field(default="/akash.epochs.v1beta1.QueryCurrentEpochResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryCurrentEpochResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

