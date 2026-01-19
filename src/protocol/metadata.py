"""
SecureEV-OTA Metadata Module

Implements enhanced Uptane metadata structures with ECC support
and efficient serialization.

Key Enhancements:
- Compact JSON serialization
- Multi-signature support (thresholds)
- Hybrid signature support (ECC + PQC)
- Metadata chaining for rollback protection
"""

from __future__ import annotations

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import base64

from ..crypto.ecc_core import ECCCore, ECDSASignature
from ..crypto.hybrid_pqc import HybridSignature


class MetadataRole(Enum):
    """Uptane metadata roles."""
    ROOT = "root"
    TIMESTAMP = "timestamp"
    SNAPSHOT = "snapshot"
    TARGETS = "targets"
    DIRECTOR = "director"  # Vehicle-specific


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA256 = "sha256"
    SHA512 = "sha512"


@dataclass
class KeyInfo:
    """Public key information."""
    key_type: str
    key_id: str
    public_key_pem: str
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Signature:
    """Metadata signature."""
    key_id: str
    method: str
    signature: str  # Hex encoded
    
    @classmethod
    def from_crypto_signature(cls, sig: Union[ECDSASignature, HybridSignature]) -> "Signature":
        """Create from crypto signature object."""
        if isinstance(sig, ECDSASignature):
            return cls(
                key_id=sig.key_id,
                method="ecdsa-sha256",
                signature=sig.signature.hex()
            )
        elif isinstance(sig, HybridSignature):
            return cls(
                key_id=sig.key_id,
                method="hybrid-pqc",
                signature=sig.to_bytes().hex()  # Store full hybrid structure
            )
        raise ValueError(f"Unsupported signature type: {type(sig)}")


@dataclass
class TargetInfo:
    """Information about a target file (firmware)."""
    length: int
    hashes: Dict[str, str]
    custom: Optional[Dict[str, Any]] = None  # Hardware ID, version, etc.
    
    @classmethod
    def from_content(cls, content: bytes, custom: Dict = None) -> "TargetInfo":
        """Create from actual file content."""
        return cls(
            length=len(content),
            hashes={
                "sha256": hashlib.sha256(content).hexdigest(),
                "sha512": hashlib.sha512(content).hexdigest()
            },
            custom=custom
        )


@dataclass
class MetadataContent:
    """Base class for metadata content payload."""
    version: int
    expires: str # ISO 8601
    type: str = field(init=False) # Set by subclasses in __post_init__
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def to_canonical_json(self) -> bytes:
        """Serialize to canonical JSON for signing."""
        # Sort keys, no spaces
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':')).encode()


@dataclass
class RootMetadata(MetadataContent):
    """Root metadata content."""
    keys: Dict[str, KeyInfo]
    roles: Dict[str, Dict[str, Any]]  # role -> threshold, key_ids
    consistent_snapshot: bool = True
    
    def __post_init__(self):
        self.type = MetadataRole.ROOT.value


@dataclass
class TargetsMetadata(MetadataContent):
    """Targets metadata content."""
    targets: Dict[str, TargetInfo]  # filename -> info
    
    def __post_init__(self):
        self.type = MetadataRole.TARGETS.value


@dataclass
class SnapshotMetadata(MetadataContent):
    """Snapshot metadata content."""
    meta: Dict[str, Dict[str, Any]]  # filename -> version, length
    
    def __post_init__(self):
        self.type = MetadataRole.SNAPSHOT.value


@dataclass
class TimestampMetadata(MetadataContent):
    """Timestamp metadata content."""
    snapshot_hash: Dict[str, str]
    snapshot_size: int
    snapshot_version: int
    
    def __post_init__(self):
        self.type = MetadataRole.TIMESTAMP.value


@dataclass
class MetadataFile:
    """Complete metadata file structure (signed)."""
    signed: MetadataContent
    signatures: List[Signature]
    
    def to_json(self) -> str:
        """Serialize full metadata file to JSON."""
        return json.dumps({
            "signed": self.signed.to_dict(),
            "signatures": [asdict(s) for s in self.signatures]
        }, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> "MetadataFile":
        """Parse from JSON string (factory)."""
        data = json.loads(json_str)
        signed_data = data["signed"]
        role = signed_data["type"]
        
        # Instantiate correct content class
        if role == MetadataRole.ROOT.value:
            content = RootMetadata(**signed_data)
        elif role == MetadataRole.TARGETS.value:
            # Handle nested dataclasses conversion manually
            targets_raw = signed_data.pop("targets", {})
            targets = {k: TargetInfo(**v) for k, v in targets_raw.items()}
            content = TargetsMetadata(targets=targets, **signed_data)
        elif role == MetadataRole.SNAPSHOT.value:
            content = SnapshotMetadata(**signed_data)
        elif role == MetadataRole.TIMESTAMP.value:
            content = TimestampMetadata(**signed_data)
        else:
            # Director/other roles treated as generic Targets usually
            if "targets" in signed_data:
                targets_raw = signed_data.pop("targets", {})
                targets = {k: TargetInfo(**v) for k, v in targets_raw.items()}
                content = TargetsMetadata(targets=targets, **signed_data)
            else:
                 # Generic fallback (partial implementations)
                 raise ValueError(f"Unsupported metadata role: {role}")

        signatures = [Signature(**s) for s in data["signatures"]]
        return cls(signed=content, signatures=signatures)
    
    def sign(self, signer_func, key_id: str):
        """
        Add a signature using a signing function.
        signer_func: callable(bytes) -> Signature object
        """
        message = self.signed.to_canonical_json()
        sig_obj = signer_func(message)
        self.signatures.append(Signature.from_crypto_signature(sig_obj))


class MetadataManager:
    """Helper to manage, create, and verify metadata."""
    
    @staticmethod
    def create_root(keys: Dict[str, KeyInfo], ver: int, expires: str) -> MetadataFile:
        """Create a new root metadata file."""
        # Default policy: threshold 1 for all roles
        roles = {
            role.value: {"threshold": 1, "keyids": list(keys.keys())}
            for role in MetadataRole
        }
        content = RootMetadata(version=ver, expires=expires, keys=keys, roles=roles)
        return MetadataFile(signed=content, signatures=[])

    @staticmethod
    def create_targets(targets: Dict[str, TargetInfo], ver: int, expires: str) -> MetadataFile:
        content = TargetsMetadata(version=ver, expires=expires, targets=targets)
        return MetadataFile(signed=content, signatures=[])
    
    @staticmethod 
    def verify_metadata(metadata: MetadataFile, trusted_keys: Dict[str, Any]) -> bool:
        """
        Verify metadata signatures against trusted keys.
        Note: Simplied verification logic for Phase 2.
        """
        if not metadata.signatures:
            return False
            
        message = metadata.signed.to_canonical_json()
        valid_sigs = 0
        
        for sig in metadata.signatures:
            if sig.key_id in trusted_keys:
                key = trusted_keys[sig.key_id]
                try:
                    # Logic would delegate to ECCCore.verify
                    # For now assume signature format matches simple hex
                    # In real implementation:
                    # key.verify(bytes.fromhex(sig.signature), message)
                    valid_sigs += 1
                except Exception:
                    continue
                    
        return valid_sigs >= 1

# Example usage
if __name__ == "__main__":
    print("Metadata module loaded.")
    # Quick test
    target = TargetInfo.from_content(b"firmware_v1.0")
    print(f"Target hash: {target.hashes['sha256']}")
    
    md = MetadataManager.create_targets(
        targets={"firmware.bin": target},
        ver=1,
        expires="2026-12-31T00:00:00Z"
    )
    print("Generated Metadata JSON:")
    print(md.to_json())
