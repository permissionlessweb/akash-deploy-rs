# Auto-generated from akash.base.offchain.sign.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.base.offchain.sign.v1.rs
# Package: akash.base.offchain.sign.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.base.offchain.sign.v1"

@dataclass
class MsgSignData:
    """MsgSignData defines an arbitrary, general-purpose, off-chain message"""
    # Signer is the sdk.AccAddress of the message signer
    signer: str = ""
    # Data represents the raw bytes of the content that is signed (text, json, etc)
    data: str = ""
    TYPE_URL: str = field(default="/akash.base.offchain.sign.v1.MsgSignData", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgSignData":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

