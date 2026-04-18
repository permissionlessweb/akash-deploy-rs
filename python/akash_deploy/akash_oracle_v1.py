# Auto-generated from akash.oracle.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.oracle.v1.rs
# Package: akash.oracle.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.oracle.v1"

@dataclass
class DataId:
    """DataID uniquely identifies a price pair by asset and base denomination"""
    # denom is the asset denomination (e.g., "uakt")
    denom: str = ""
    # base_denom is the base denomination for the price pair (e.g., "usd")
    base_denom: str = ""
    TYPE_URL: str = field(default="/akash.oracle.v1.DataID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "DataId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PriceDataId:
    """PriceDataID identifies price data from a specific source for a specific pair"""
    # source is the index of the price source (oracle provider)
    source: int = 0
    # denom is the asset denomination
    denom: str = ""
    # base_denom is the base denomination for the price pair
    base_denom: str = ""
    TYPE_URL: str = field(default="/akash.oracle.v1.PriceDataID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PriceDataId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PriceDataRecordId:
    """PriceDataRecordID represents a price from a specific source at a specific time. It also represents a single data point in TWAP history"""
    # source is the index of the price source (oracle provider)
    source: int = 0
    # denom is the asset denomination
    denom: str = ""
    # base_denom is the base denomination for the price pair
    base_denom: str = ""
    # height is the block height when this price was recorded
    height: str = "0"
    TYPE_URL: str = field(default="/akash.oracle.v1.PriceDataRecordID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PriceDataRecordId":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PriceDataState:
    """PriceDataState represents the price value and timestamp for a price entry"""
    # price is the decimal price value
    price: str = ""
    # timestamp is when the price was recorded
    timestamp: Optional[Any  # Timestamp] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.PriceDataState", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PriceDataState":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PriceData:
    """PriceData combines a price record identifier with its state"""
    # id uniquely identifies this price record
    id: Optional[PriceDataRecordId] = None
    # state contains the price value and timestamp
    state: Optional[PriceDataState] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.PriceData", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PriceData":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class AggregatedPrice:
    """AggregatedPrice represents the final aggregated price from all sources"""
    # denom is the asset denomination
    denom: str = ""
    # twap is the time-weighted average price over the configured window
    twap: str = ""
    # median_price is the median of all source prices
    median_price: str = ""
    # min_price is the minimum price from all sources
    min_price: str = ""
    # max_price is the maximum price from all sources
    max_price: str = ""
    # timestamp is when the aggregated price was computed
    timestamp: Optional[Any  # Timestamp] = None
    # num_sources is the number of price sources contributing to this aggregation
    num_sources: int = 0
    # deviation_bps is the price deviation in basis points between min and max prices
    deviation_bps: str = "0"
    TYPE_URL: str = field(default="/akash.oracle.v1.AggregatedPrice", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "AggregatedPrice":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PriceHealth:
    """PriceHealth represents the health status of a price feed"""
    # denom is the asset denomination
    denom: str = ""
    # is_healthy indicates if the price feed meets all health requirements
    is_healthy: bool = False
    # has_min_sources indicates if minimum number of sources are reporting
    has_min_sources: bool = False
    # deviation_ok indicates if price deviation is within acceptable limits
    deviation_ok: bool = False
    # total_sources indicates total amount of sources registered for price calculations
    total_sources: int = 0
    # total_healthy_sources indicates total usable sources for price calculations
    total_healthy_sources: int = 0
    # failure_reason lists reasons for unhealthy status, if any
    failure_reason: List[str] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.oracle.v1.PriceHealth", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PriceHealth":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PricesFilter:
    """PricesFilter defines filters used to query price data"""
    # asset_denom is the asset denomination to filter by
    asset_denom: str = ""
    # base_denom is the base denomination to filter by
    base_denom: str = ""
    # height is the block height to filter by
    height: str = "0"
    TYPE_URL: str = field(default="/akash.oracle.v1.PricesFilter", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PricesFilter":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryPricesRequest:
    """QueryPricesRequest is the request type for querying price history"""
    # filters holds the price fields to filter the request
    filters: Optional[PricesFilter] = None
    # pagination is used to paginate the request
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryPricesRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryPricesRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryPricesResponse:
    """QueryPricesResponse is the response type for querying price history"""
    # prices is the list of historical price data matching the filters
    prices: List[PriceData] = field(default_factory=list)
    # pagination contains the information about response pagination
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryPricesResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryPricesResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventPriceData:
    """EventPriceData is emitted when new price data is added to the oracle"""
    # source is the address of the price source (oracle provider)
    source: str = ""
    # id identifies the price pair (denom and base_denom)
    id: Optional[DataId] = None
    # data contains the price value and timestamp
    data: Optional[PriceDataState] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.EventPriceData", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventPriceData":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventPriceStaleWarning:
    """EventPriceStaleWarning is emitted when price has not been updated and is about to become stale"""
    # source is the address of the price source
    source: str = ""
    # id identifies the price pair
    id: Optional[DataId] = None
    # last_height is the block height when the price was last updated
    last_height: str = "0"
    # blocks_to_stall is the number of blocks until the price becomes stale
    blocks_to_stall: str = "0"
    TYPE_URL: str = field(default="/akash.oracle.v1.EventPriceStaleWarning", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventPriceStaleWarning":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventPriceStaled:
    """EventPriceStaled is emitted when a price has become stale"""
    # source is the address of the price source
    source: str = ""
    # id identifies the price pair
    id: Optional[DataId] = None
    # last_height is the block height when the price was last updated before becoming stale
    last_height: str = "0"
    TYPE_URL: str = field(default="/akash.oracle.v1.EventPriceStaled", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventPriceStaled":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class EventPriceRecovered:
    """EventPriceRecovered is emitted when a stale price has started receiving updates again"""
    # source is the address of the price source
    source: str = ""
    # id identifies the price pair
    id: Optional[DataId] = None
    # height is the block height when the price recovery was detected
    height: str = "0"
    TYPE_URL: str = field(default="/akash.oracle.v1.EventPriceRecovered", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "EventPriceRecovered":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class PythContractParams:
    """PythContractParams contains configuration for Pyth price feeds"""
    # akt_price_feed_id is the Pyth price feed identifier for AKT/USD
    akt_price_feed_id: str = ""
    TYPE_URL: str = field(default="/akash.oracle.v1.PythContractParams", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "PythContractParams":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Params:
    """Params defines the parameters for the oracle module"""
    # sources addresses allowed to write prices into oracle module those are to be smartcontract addresses
    sources: List[str] = field(default_factory=list)
    # Minimum number of price sources required (default: 2)
    min_price_sources: int = 0
    # Maximum price staleness in blocks (default: 50 = ~ 5 minutes)
    max_price_staleness_blocks: str = "0"
    # TWAP window in blocks (default: 50 = ~ 5 minutes)
    twap_window: str = "0"
    # Maximum price deviation in basis points (default: 150 = 1.5%)
    max_price_deviation_bps: str = "0"
    # feed_contracts_params contains the configuration for the price feed contracts
    feed_contracts_params: List[Any] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.oracle.v1.Params", init=False, repr=False)

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
    """QueryParamsRequest is the request type for the Query/Params RPC method."""
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryParamsRequest", init=False, repr=False)

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
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryParamsResponse", init=False, repr=False)

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
class QueryPriceFeedConfigRequest:
    """QueryPriceFeedConfigRequest is the request type for price feed config."""
    # denom is the denomination to query the price feed configuration for
    denom: str = ""
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryPriceFeedConfigRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryPriceFeedConfigRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryPriceFeedConfigResponse:
    """QueryPriceFeedConfigResponse is the response type for price feed config."""
    # price_feed_id is the Pyth price feed identifier for this denomination
    price_feed_id: str = ""
    # pyth_contract_address is the address of the Pyth smart contract
    pyth_contract_address: str = ""
    # enabled indicates if the price feed is enabled for this denomination
    enabled: bool = False
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryPriceFeedConfigResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryPriceFeedConfigResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryAggregatedPriceRequest:
    """QueryAggregatedPriceRequest is the request type for aggregated price."""
    # denom is the asset denomination
    denom: str = ""
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryAggregatedPriceRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryAggregatedPriceRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryAggregatedPriceResponse:
    """QueryAggregatedPriceResponse is the response type for aggregated price."""
    # aggregated_price is the aggregated price data
    aggregated_price: Optional[AggregatedPrice] = None
    # price_health is the health status for the price feed
    price_health: Optional[PriceHealth] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.QueryAggregatedPriceResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryAggregatedPriceResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgAddPriceEntry:
    """MsgAddPriceEntry defines an SDK message to add oracle price entry."""
    # Signer is the bech32 address of the account of the provider. It is a string representing a valid account address.  Example: "akash1..."
    signer: str = ""
    # id uniquely identifies the price data by denomination and base denomination
    id: Optional[DataId] = None
    # price contains the price value and timestamp for this entry
    price: Optional[PriceDataState] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.MsgAddPriceEntry", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgAddPriceEntry":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgAddPriceEntryResponse:
    """MsgAddPriceEntryResponse defines the Msg/MsgAddDPriceEntry response type."""
    TYPE_URL: str = field(default="/akash.oracle.v1.MsgAddPriceEntryResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgAddPriceEntryResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgUpdateParams:
    """MsgUpdateParams is the Msg/UpdateParams request type.  Since: akash v2.0.0"""
    # authority is the address of the governance account.
    authority: str = ""
    # params defines the x/oracle parameters to update.  NOTE: All parameters must be supplied.
    params: Optional[Params] = None
    TYPE_URL: str = field(default="/akash.oracle.v1.MsgUpdateParams", init=False, repr=False)

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
    """MsgUpdateParamsResponse defines the response structure for executing a MsgUpdateParams message.  Since: akash v2.0.0"""
    TYPE_URL: str = field(default="/akash.oracle.v1.MsgUpdateParamsResponse", init=False, repr=False)

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
class GenesisState:
    """GenesisState defines the oracle module's genesis state"""
    # params holds the oracle module parameters
    params: Optional[Params] = None
    # prices is the list of all historical price data entries
    prices: List[PriceData] = field(default_factory=list)
    # latest_height tracks the most recent block height for each price feed source
    latest_height: List[PriceDataId] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.oracle.v1.GenesisState", init=False, repr=False)

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

