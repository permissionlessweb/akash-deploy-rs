# Auto-generated from akash.base.deposit.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.base.deposit.v1.rs
# Package: akash.base.deposit.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.base.deposit.v1"

@dataclass
class Deposit:
    """Deposit is a data type used by MsgCreateDeployment, MsgDepositDeployment and MsgCreateBid to indicate source of the deposit."""
    # amount specifies the amount of coins to include in the deployment's first deposit.
    amount: Optional[Any  # Any] = None
    # Sources is the set of deposit sources, each entry must be unique.
    sources: int = 0
    TYPE_URL: str = field(default="/akash.base.deposit.v1.Deposit", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Deposit":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

