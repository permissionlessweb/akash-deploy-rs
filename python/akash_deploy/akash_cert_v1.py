# Auto-generated from akash.cert.v1 — do not edit.
# Source: terp-rs/proto/src/gen/akash.cert.v1.rs
# Package: akash.cert.v1
# Run `just py-gen` to regenerate.
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional

PACKAGE = "akash.cert.v1"

@dataclass
class CertificateFilter:
    """CertificateFilter defines filters used to filter certificates."""
    # Owner is the account address of the user who owns the certificate. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Serial is a sequence number for the certificate.
    serial: str = ""
    # State is the state of the certificate. CertificateValid denotes state for deployment active. CertificateRevoked denotes state for deployment closed.
    state: str = ""
    TYPE_URL: str = field(default="/akash.cert.v1.CertificateFilter", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "CertificateFilter":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Id:
    """ID stores owner and sequence number."""
    # Owner is the account address of the user who owns the certificate. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Serial is a sequence number for the certificate.
    serial: str = ""
    TYPE_URL: str = field(default="/akash.cert.v1.ID", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Id":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class Certificate:
    """Certificate stores state, certificate and it's public key. The certificate is required for several transactions including deployment of a workload to verify the identity of the tenant and secure the deployment."""
    # State is the state of the certificate. CertificateValid denotes state for deployment active. CertificateRevoked denotes state for deployment closed.
    state: int = 0
    # Cert holds the bytes of the certificate.
    cert: str = ""
    # PubKey holds the public key of the certificate.
    pubkey: str = ""
    TYPE_URL: str = field(default="/akash.cert.v1.Certificate", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "Certificate":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class CertificateResponse:
    """CertificateResponse contains a single X509 certificate and its serial number."""
    # Certificate holds the certificate.
    certificate: Optional[Certificate] = None
    # Serial is a sequence number for the certificate.
    serial: str = ""
    TYPE_URL: str = field(default="/akash.cert.v1.CertificateResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "CertificateResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryCertificatesRequest:
    """QueryDeploymentsRequest is request type for the Query/Deployments RPC method."""
    # Filter allows for filtering of results.
    filter: Optional[CertificateFilter] = None
    # Pagination is used to paginate the request.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.cert.v1.QueryCertificatesRequest", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryCertificatesRequest":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class QueryCertificatesResponse:
    """QueryCertificatesResponse is response type for the Query/Certificates RPC method."""
    # Certificates is a list of certificate.
    certificates: List[CertificateResponse] = field(default_factory=list)
    # Pagination contains the information about response pagination.
    pagination: Optional[Any  # Any] = None
    TYPE_URL: str = field(default="/akash.cert.v1.QueryCertificatesResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "QueryCertificatesResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateCertificate:
    """MsgCreateCertificate defines an SDK message for creating certificate."""
    # Owner is the account address of the user who owns the certificate. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Cert holds the bytes representing the certificate.
    cert: str = ""
    # PubKey holds the public key.
    pubkey: str = ""
    TYPE_URL: str = field(default="/akash.cert.v1.MsgCreateCertificate", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateCertificate":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgCreateCertificateResponse:
    """MsgCreateCertificateResponse defines the Msg/CreateCertificate response type."""
    TYPE_URL: str = field(default="/akash.cert.v1.MsgCreateCertificateResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgCreateCertificateResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgRevokeCertificate:
    """MsgRevokeCertificate defines an SDK message for revoking certificate."""
    # Id corresponds to the certificate ID which includes owner and sequence number.
    id: Optional[Id] = None
    TYPE_URL: str = field(default="/akash.cert.v1.MsgRevokeCertificate", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgRevokeCertificate":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class MsgRevokeCertificateResponse:
    """MsgRevokeCertificateResponse defines the Msg/RevokeCertificate response type."""
    TYPE_URL: str = field(default="/akash.cert.v1.MsgRevokeCertificateResponse", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "MsgRevokeCertificateResponse":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisCertificate:
    """GenesisCertificate defines certificate entry at genesis."""
    # Owner is the account address of the user who owns the certificate. It is a string representing a valid account address.  Example: "akash1..."
    owner: str = ""
    # Certificate holds the certificate.
    certificate: Optional[Certificate] = None
    TYPE_URL: str = field(default="/akash.cert.v1.GenesisCertificate", init=False, repr=False)

    def encode(self) -> bytes:
        """Encode to protobuf binary (requires native extension)."""
        from akash_deploy._native import encode_message  # type: ignore[import]
        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())

    @classmethod
    def decode(cls, data: bytes) -> "GenesisCertificate":
        """Decode from protobuf binary (requires native extension)."""
        from akash_deploy._native import decode_message  # type: ignore[import]
        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class GenesisState:
    """GenesisState defines the basic genesis state used by cert module."""
    # Certificates is a list of genesis certificates.
    certificates: List[GenesisCertificate] = field(default_factory=list)
    TYPE_URL: str = field(default="/akash.cert.v1.GenesisState", init=False, repr=False)

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

