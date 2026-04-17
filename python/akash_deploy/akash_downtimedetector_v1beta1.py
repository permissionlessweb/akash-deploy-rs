# Auto-generated from akash.downtimedetector.v1beta1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.downtimedetector.v1beta1.rs
# Package: akash.downtimedetector.v1beta1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.downtimedetector.v1beta1"

@dataclass
class RecoveredSinceDowntimeOfLengthRequest:
    """RecoveredSinceDowntimeOfLengthRequest is the request type for querying if the chain has been operational for at least the specified recovery duration since experiencing downtime of the specified length"""
    # downtime is the downtime duration to check against
    downtime: int = 0
    # recovery is the minimum recovery duration required since the downtime
    recovery: Optional[Any  # Duration] = None
    TYPE_URL: str = field(default="/akash.downtimedetector.v1beta1.RecoveredSinceDowntimeOfLengthRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "RecoveredSinceDowntimeOfLengthRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class RecoveredSinceDowntimeOfLengthResponse:
    """RecoveredSinceDowntimeOfLengthResponse is the response type for the recovery query"""
    # succesfully_recovered indicates if the chain has been up for at least the recovery duration since the last downtime of the specified length
    succesfully_recovered: bool = False
    TYPE_URL: str = field(default="/akash.downtimedetector.v1beta1.RecoveredSinceDowntimeOfLengthResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "RecoveredSinceDowntimeOfLengthResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisDowntimeEntry:
    """GenesisDowntimeEntry tracks the last occurrence of a specific downtime duration"""
    # duration is the downtime period being tracked
    duration: int = 0
    # last_downtime is the timestamp when this downtime duration was last observed
    last_downtime: Optional[Any  # Timestamp] = None
    TYPE_URL: str = field(default="/akash.downtimedetector.v1beta1.GenesisDowntimeEntry", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisDowntimeEntry":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the downtime detector module's genesis state"""
    # downtimes is the list of tracked downtime entries
    downtimes: List[GenesisDowntimeEntry] = field(default_factory=list)
    # last_block_time is the timestamp of the last processed block
    last_block_time: Optional[Any  # Timestamp] = None
    TYPE_URL: str = field(default="/akash.downtimedetector.v1beta1.GenesisState", init=False, repr=False)

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

