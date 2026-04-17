# Auto-generated from akash.bme.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.bme.v1.rs
# Package: akash.bme.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.bme.v1"

@dataclass
class LedgerId:
    """LedgerID uniquely identifies a ledger entry by block height and sequence number"""
    # height is the block height when the ledger entry was created
    height: str = "0"
    # sequence is the sequence number within the block (for ordering)
    sequence: str = "0"
    TYPE_URL: str = field(default="/akash.bme.v1.LedgerID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "LedgerId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class CollateralRatio:
    """CollateralRatio represents the current collateral ratio"""
    # ratio is CR = (VaultAKT * Price) / OutstandingACT
    ratio: str = ""
    # status indicates the current circuit breaker status
    status: int = 0
    # reference_price is the price used to calculate CR
    reference_price: str = ""
    TYPE_URL: str = field(default="/akash.bme.v1.CollateralRatio", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "CollateralRatio":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class State:
    """State tracks net burn metrics since BME start"""
    # burned is the cumulative burn for tracked tokens
    balances: List[Any] = field(default_factory=list)
    # burned is the cumulative burn for tracked tokens
    total_burned: List[Any] = field(default_factory=list)
    # minted is the cumulative mint back for tracked tokens
    total_minted: List[Any] = field(default_factory=list)
    # remint_credits tracks available credits for reminting tokens (e.g., from previous burns that can be reminted without additional collateral)
    remint_credits: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.bme.v1.State", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "State":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class CoinPrice:
    """CoinPrice represents a coin amount with its associated oracle price at a specific point in time"""
    # coin is the token amount
    coin: Optional[Any  # Coin] = None
    # price (at oracle) of the coin at burn/mint event
    price: str = ""
    TYPE_URL: str = field(default="/akash.bme.v1.CoinPrice", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "CoinPrice":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class BurnMintPair:
    """BurnMintPair represents a pair of burn and mint operations with their respective prices"""
    # burned is the coin burned
    burned: Optional[CoinPrice] = None
    # minted is coin minted
    minted: Optional[CoinPrice] = None
    TYPE_URL: str = field(default="/akash.bme.v1.BurnMintPair", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "BurnMintPair":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class LedgerRecordId:
    """LedgerRecordID"""
    # denom is the asset denomination
    denom: str = ""
    # to_denom is what denom swap to
    to_denom: str = ""
    source: str = ""
    height: str = "0"
    sequence: str = "0"
    TYPE_URL: str = field(default="/akash.bme.v1.LedgerRecordID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "LedgerRecordId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class LedgerPendingRecord:
    """LedgerPendingRecord"""
    # owner source of the coins to be burned
    owner: str = ""
    # to destination of the minted coins. if minted coin is ACT, "to" must be same as signer
    to: str = ""
    # coins_to_burn
    coins_to_burn: Optional[Any  # Any] = None
    # denom_to_mint
    denom_to_mint: str = ""
    TYPE_URL: str = field(default="/akash.bme.v1.LedgerPendingRecord", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "LedgerPendingRecord":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class LedgerRecord:
    """LedgerRecord stores information of burn/mint event of token A burn to mint token B"""
    # burned_from source address of the tokens burned
    burned_from: str = ""
    # minted_to destination address of the tokens minted
    minted_to: str = ""
    # module is module account performing burn
    burner: str = ""
    # module is module account performing mint
    minter: str = ""
    # burned is the coin burned at price
    burned: Optional[CoinPrice] = None
    # minted is coin minted at price
    minted: Optional[CoinPrice] = None
    remint_credit_issued: Optional[CoinPrice] = None
    remint_credit_accrued: Optional[CoinPrice] = None
    TYPE_URL: str = field(default="/akash.bme.v1.LedgerRecord", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "LedgerRecord":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Status:
    """Status stores status of mint operations"""
    status: int = 0
    previous_status: int = 0
    epoch_height_diff: str = "0"
    TYPE_URL: str = field(default="/akash.bme.v1.Status", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Status":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MintEpoch:
    """MintEpoch stores information about mint epoch"""
    next_epoch: str = "0"
    TYPE_URL: str = field(default="/akash.bme.v1.MintEpoch", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MintEpoch":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventMintStatusChange:
    """EventCircuitBreakerStatusChange is emitted when circuit breaker status changes"""
    # previous_status is the previous status
    previous_status: int = 0
    # new_status is the new status
    new_status: int = 0
    # collateral_ratio is the CR that triggered the change
    collateral_ratio: str = ""
    TYPE_URL: str = field(default="/akash.bme.v1.EventMintStatusChange", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventMintStatusChange":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventVaultSeeded:
    """EventVaultSeeded is emitted when the vault is seeded with AKT"""
    # amount is the AKT amount added to vault
    amount: Optional[Any  # Coin] = None
    # source is where the funds came from
    source: str = ""
    # new_vault_balance is the new vault balance
    new_vault_balance: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.bme.v1.EventVaultSeeded", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventVaultSeeded":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventLedgerRecordExecuted:
    """EventLedgerRecordExecuted emitted information of burn/mint event of token A burn to mint token B"""
    # burned_from source address of the tokens burned
    id: Optional[LedgerRecordId] = None
    TYPE_URL: str = field(default="/akash.bme.v1.EventLedgerRecordExecuted", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventLedgerRecordExecuted":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Params:
    """Params defines the parameters for the BME module"""
    # circuit_breaker_warn_threshold is the CR below which warning is triggered Stored as basis points * 100 (e.g., 9500 = 0.95)
    circuit_breaker_warn_threshold: int = 0
    # circuit_breaker_halt_threshold is the CR below which mints are halted Stored as basis points * 100 (e.g., 9000 = 0.90)
    circuit_breaker_halt_threshold: int = 0
    # min_epoch_blocks is the minimum amount of blocks required for ACT mints
    min_epoch_blocks: str = "0"
    # epoch_blocks_backoff increase of runway_blocks in % during warn threshold for drop in 1 basis point of circuit_breaker_warn_threshold Stored as basis points * 100 (e.g., 9500 = 0.95) e.g: runway_blocks = 100 min_runway_blocks_backoff = 1000 circuit_breaker_warn_threshold drops from 0.95 to 0.94 then runway_blocks = (100\*0.1 + 100) = 110  ```text circuit_breaker_warn_threshold drops from 0.94 to 0.92 then runway_blocks = (110*(0.1*2) + 110) = 132 ```
    epoch_blocks_backoff: int = 0
    # mint_spread_bps is the spread in basis points applied during ACT mint (default: 25 bps = 0.25%)
    mint_spread_bps: int = 0
    # settle_spread_bps is the spread in basis points applied during settlement (default: 0 for no provider tax)
    settle_spread_bps: int = 0
    TYPE_URL: str = field(default="/akash.bme.v1.Params", init=False, repr=False)

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
class QueryParamsRequest:
    """QueryParamsRequest is the request type for the Query/Params RPC method"""
    TYPE_URL: str = field(default="/akash.bme.v1.QueryParamsRequest", init=False, repr=False)

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
    """QueryParamsResponse is the response type for the Query/Params RPC method"""
    params: Optional[Params] = None
    TYPE_URL: str = field(default="/akash.bme.v1.QueryParamsResponse", init=False, repr=False)

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
class QueryVaultStateRequest:
    """QueryVaultStateRequest is the request type for the Query/VaultState RPC method"""
    TYPE_URL: str = field(default="/akash.bme.v1.QueryVaultStateRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryVaultStateRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryVaultStateResponse:
    """QueryVaultStateResponse is the response type for the Query/VaultState RPC method"""
    vault_state: Optional[State] = None
    TYPE_URL: str = field(default="/akash.bme.v1.QueryVaultStateResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryVaultStateResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryStatusRequest:
    """QueryStatusRequest is the request type for the circuit breaker status"""
    TYPE_URL: str = field(default="/akash.bme.v1.QueryStatusRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryStatusRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryStatusResponse:
    """QueryMintStatusResponse is the response type for the circuit breaker status"""
    # status is the current circuit breaker status
    status: int = 0
    # collateral_ratio is the current CR
    collateral_ratio: str = ""
    # warn_threshold is the warning threshold
    warn_threshold: str = ""
    # halt_threshold is the halt threshold
    halt_threshold: str = ""
    # mints_allowed indicates if new ACT mints are allowed
    mints_allowed: bool = False
    # refunds_allowed indicates if ACT refunds are allowed
    refunds_allowed: bool = False
    TYPE_URL: str = field(default="/akash.bme.v1.QueryStatusResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryStatusResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateParams:
    """MsgUpdateParams defines the message for updating module parameters"""
    # authority is the address that controls the module (governance)
    authority: str = ""
    # params defines the updated parameters
    params: Optional[Params] = None
    TYPE_URL: str = field(default="/akash.bme.v1.MsgUpdateParams", init=False, repr=False)

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
    """MsgUpdateParamsResponse is the response type for MsgUpdateParams"""
    TYPE_URL: str = field(default="/akash.bme.v1.MsgUpdateParamsResponse", init=False, repr=False)

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
class MsgSeedVault:
    """MsgSeedVault defines the message for seeding the BME vault with AKT This is used to provide an initial volatility buffer"""
    # authority is the address that controls the module (governance)
    authority: str = ""
    # amount is the AKT amount to seed the vault with
    amount: Optional[Any  # Coin] = None
    # source is the source of funds (e.g., community pool)
    source: str = ""
    TYPE_URL: str = field(default="/akash.bme.v1.MsgSeedVault", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgSeedVault":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgSeedVaultResponse:
    """MsgSeedVaultResponse is the response type for MsgSeedVault"""
    # vault_akt is the new vault AKT balance
    vault_akt: str = ""
    TYPE_URL: str = field(default="/akash.bme.v1.MsgSeedVaultResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgSeedVaultResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgBurnMint:
    """MsgBurnMint defines the message for burning one token to mint another Allows burning AKT to mint ACT, or burning unused ACT back to AKT"""
    # owner source of the coins to be burned
    owner: str = ""
    # to destination of the minted coins. if minted coin is ACT, "to" must be same as signer
    to: str = ""
    # coins_to_burn
    coins_to_burn: Optional[Any  # Any] = None
    # denom_to_mint
    denom_to_mint: str = ""
    TYPE_URL: str = field(default="/akash.bme.v1.MsgBurnMint", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgBurnMint":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgMintAct:
    """MsgMintACT defines the message for burning one token to mint another Allows burning AKT to mint ACT, or burning unused ACT back to AKT"""
    # owner source of the coins to be burned
    owner: str = ""
    # to destination of the minted coins. if minted coin is ACT, "to" must be same as signer
    to: str = ""
    # coins_to_burn
    coins_to_burn: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.bme.v1.MsgMintACT", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgMintAct":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgBurnAct:
    """MsgMintACT defines the message for burning one token to mint another Allows burning AKT to mint ACT, or burning unused ACT back to AKT"""
    # owner source of the coins to be burned
    owner: str = ""
    # to destination of the minted coins. if minted coin is ACT, "to" must be same as signer
    to: str = ""
    # coins_to_burn
    coins_to_burn: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.bme.v1.MsgBurnACT", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgBurnAct":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgBurnMintResponse:
    """MsgBurnMintResponse is the response type for MsgBurnMint"""
    id: Optional[LedgerRecordId] = None
    status: int = 0
    TYPE_URL: str = field(default="/akash.bme.v1.MsgBurnMintResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgBurnMintResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgMintActResponse:
    """MsgBurnMintResponse is the response type for MsgBurnMint"""
    id: Optional[LedgerRecordId] = None
    status: int = 0
    TYPE_URL: str = field(default="/akash.bme.v1.MsgMintACTResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgMintActResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgBurnActResponse:
    """MsgBurnMintResponse is the response type for MsgBurnMint"""
    id: Optional[LedgerRecordId] = None
    status: int = 0
    TYPE_URL: str = field(default="/akash.bme.v1.MsgBurnACTResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgBurnActResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisLedgerRecord:
    """GenesisLedgerRecord"""
    id: Optional[LedgerRecordId] = None
    record: Optional[LedgerRecord] = None
    TYPE_URL: str = field(default="/akash.bme.v1.GenesisLedgerRecord", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisLedgerRecord":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisLedgerPendingRecord:
    """GenesisLedgerPendingRecord"""
    id: Optional[LedgerRecordId] = None
    record: Optional[LedgerPendingRecord] = None
    TYPE_URL: str = field(default="/akash.bme.v1.GenesisLedgerPendingRecord", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisLedgerPendingRecord":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisLedgerState:
    """GenesisLedgerState"""
    records: List[GenesisLedgerRecord] = field(default_factory=list)
    pending_records: List[GenesisLedgerPendingRecord] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.bme.v1.GenesisLedgerState", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisLedgerState":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisVaultState:
    """GenesisVaultState"""
    # burned is the cumulative burn for tracked tokens
    total_burned: List[Any] = field(default_factory=list)
    # minted is the cumulative mint back for tracked tokens
    total_minted: List[Any] = field(default_factory=list)
    # remint_credits tracks available credits for reminting tokens (e.g., from previous burns that can be reminted without additional collateral)
    remint_credits: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.bme.v1.GenesisVaultState", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisVaultState":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the BME module's genesis state"""
    # params defines the module parameters
    params: Optional[Params] = None
    # state is the initial vault state
    state: Optional[GenesisVaultState] = None
    ledger: Optional[GenesisLedgerState] = None
    TYPE_URL: str = field(default="/akash.bme.v1.GenesisState", init=False, repr=False)

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

