"""
SecureEV-OTA: Uptane Protocol Implementation

This module provides the core data structures and logic for the Uptane protocol,
managing the metadata roles (Root, Targets, Snapshot, Timestamp) and their
verification.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import hashlib

from src.crypto.ecc_core import ECCCore, ECDSASignature, ECCCurve, ECCKeyPair, public_key_from_bytes


@dataclass
class Role:
    """Base class for Uptane roles."""
    name: str
    threshold: int
    key_ids: List[str]


@dataclass
class Metadata:
    """Base class for signed metadata."""
    expires: str
    version: int
    role: str = ""
    signatures: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "signed": self.signed_part(),
            "signatures": self.signatures
        }
        
    def signed_part(self) -> Dict[str, Any]:
        """Return the part of the metadata that is signed."""
        return {
            "_type": self.role,
            "expires": self.expires,
            "version": self.version
        }
        
    def sign(self, keypair: ECCKeyPair, ecc: ECCCore) -> None:
        """
        Sign the metadata with the given key.
        
        Args:
            keypair: Key pair to sign with
            ecc: ECC engine instance
        """
        canonical = json.dumps(self.signed_part(), sort_keys=True).encode()
        sig_obj = ecc.sign(keypair.private_key, canonical, keypair.key_id)
        
        self.signatures.append(sig_obj.to_dict())


@dataclass
class RootMetadata(Metadata):
    """
    Root metadata: The trust anchor.
    Contains public keys for all top-level roles.
    """
    keys: Dict[str, Dict[str, str]] = field(default_factory=dict)
    roles: Dict[str, Role] = field(default_factory=dict)
    
    def __post_init__(self):
        self.role = "root"
        
    def signed_part(self) -> Dict[str, Any]:
        base = super().signed_part()
        base["keys"] = self.keys
        # Convert Roles to dicts
        role_dicts = {}
        for name, role in self.roles.items():
            role_dicts[name] = {
                "threshold": role.threshold,
                "keyids": role.key_ids
            }
        base["roles"] = role_dicts
        return base
        
    def add_key(self, keypair: ECCKeyPair):
        """Add a public key to the trusted set."""
        self.keys[keypair.key_id] = {
            "keytype": f"ecdsa-{keypair.curve.value}",
            "keyval": {
                "public": keypair.get_public_key_bytes().hex()
            }
        }
        
    def add_role(self, name: str, threshold: int, key_ids: List[str]):
        """Define a role's trust policy."""
        self.roles[name] = Role(name, threshold, key_ids)


@dataclass
class TargetsMetadata(Metadata):
    """
    Targets metadata: Describes available firmware images.
    """
    targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        self.role = "targets"
        
    def signed_part(self) -> Dict[str, Any]:
        base = super().signed_part()
        base["targets"] = self.targets
        return base
        
    def add_target(self, filename: str, file_hash: str, length: int, hardware_id: str):
        """Add a firmware target."""
        self.targets[filename] = {
            "hashes": {"sha256": file_hash},
            "length": length,
            "custom": {"hardwareId": hardware_id}
        }


@dataclass
class SnapshotMetadata(Metadata):
    """
    Snapshot metadata: Version control for other metadata.
    Ensures that clients see a consistent view of the repository.
    """
    meta: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        self.role = "snapshot"
        
    def signed_part(self) -> Dict[str, Any]:
        base = super().signed_part()
        base["meta"] = self.meta
        return base
        
    def add_metadata_version(self, filename: str, version: int):
        """Record the version of a metadata file."""
        self.meta[filename] = {"version": version}


@dataclass
class TimestampMetadata(Metadata):
    """
    Timestamp metadata: Indicates freshness.
    Short expiry, updated frequently to alert clients of new updates.
    """
    snapshot_hash: str = ""
    snapshot_size: int = 0
    
    def __post_init__(self):
        self.role = "timestamp"
        
    def signed_part(self) -> Dict[str, Any]:
        base = super().signed_part()
        base["meta"] = {
            "snapshot.json": {
                "hashes": {"sha256": self.snapshot_hash},
                "length": self.snapshot_size
            }
        }
        return base
