"""
SecureEV-OTA: Metadata Manager

This module handles the loading, verification, and management of Uptane metadata.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import logging

from src.crypto.ecc_core import ECCCore, public_key_from_bytes, ECCCurve
from src.uptane.metadata import RootMetadata, TargetsMetadata, SnapshotMetadata, TimestampMetadata, Metadata

logger = logging.getLogger(__name__)

class MetadataVerificationError(Exception):
    """Raised when metadata verification fails."""
    pass

class MetadataManager:
    """
    Manages the lifecycle and verification of Uptane metadata.
    """
    
    def __init__(self, ecc_core: ECCCore = None):
        self.ecc = ecc_core or ECCCore()
        # Trusted keys (key_id -> public_key_obj)
        self.trusted_keys: Dict[str, Any] = {}
        
    def load_trusted_root(self, root_json: str):
        """
        Load an initial trusted root metadata file.
        This provides the initial set of keys to verify everything else.
        """
        data = json.loads(root_json)
        # In a real scenario, we'd verify this against a hardcoded root key or pinned key
        # For now, we trust the provided root content to bootstrap
        self._import_keys_from_root(data)
        
    def _import_keys_from_root(self, root_data: Dict[str, Any]):
        """Parse keys from root metadata and store them."""
        keys = root_data["signed"]["keys"]
        for key_id, key_info in keys.items():
            try:
                pub_bytes = bytes.fromhex(key_info["keyval"]["public"])
                # Assume P-256 for now, can infer from keytype later
                pub_key = public_key_from_bytes(pub_bytes, ECCCurve.SECP256R1)
                self.trusted_keys[key_id] = pub_key
            except Exception as e:
                logger.warning(f"Failed to load key {key_id}: {e}")

    def verify_metadata(self, metadata_json: str, role: str) -> Metadata:
        """
        Verify and load a metadata file.
        
        Checks:
        1. Signature validity (using trusted keys)
        2. Expiration
        3. Role match
        """
        try:
            data = json.loads(metadata_json)
        except json.JSONDecodeError:
            raise MetadataVerificationError("Invalid JSON format")

        signed = data["signed"]
        signatures = data["signatures"]

        # 1. Check Role
        if signed["_type"] != role:
            raise MetadataVerificationError(f"Expected role {role}, got {signed['_type']}")

        # 2. Check Expiry
        expires = datetime.fromisoformat(signed["expires"].replace("Z", "+00:00"))
        # Ensure comparison is robust (aware vs naive)
        if expires.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.utcnow()
            
        if expires < now:
            raise MetadataVerificationError(f"Metadata expired on {expires}")

        # 3. Verify Signatures
        # We need to canonicalize the signed part exactly as it was signed
        canonical_bytes = json.dumps(signed, sort_keys=True).encode()
        
        valid_sigs = 0
        for sig in signatures:
            key_id = sig["key_id"]
            if key_id not in self.trusted_keys:
                continue
                
            public_key = self.trusted_keys[key_id]
            sig_bytes = bytes.fromhex(sig["signature"])
            
            if self.ecc.verify(public_key, sig_bytes, canonical_bytes):
                valid_sigs += 1
        
        if valid_sigs == 0:
            raise MetadataVerificationError("No valid signatures found from trusted keys")

        # 4. Return Object
        return self._create_object(role, signed, signatures)

    def _create_object(self, role: str, signed: Dict, signatures: List) -> Metadata:
        """Factory to create specific metadata objects."""
        common_args = {
            "expires": signed["expires"],
            "version": signed["version"],
            "signatures": signatures
        }
        
        if role == "root":
            return RootMetadata(
                **common_args, 
                keys=signed["keys"], 
                roles=signed["roles"]
            )
        elif role == "targets":
            return TargetsMetadata(
                **common_args,
                targets=signed["targets"]
            )
        elif role == "snapshot":
            return SnapshotMetadata(
                **common_args,
                meta=signed["meta"]
            )
        elif role == "timestamp":
            # Extract snapshot info from meta
            snap_info = signed["meta"]["snapshot.json"]
            return TimestampMetadata(
                **common_args,
                snapshot_hash=snap_info["hashes"]["sha256"],
                snapshot_size=snap_info["length"]
            )
        else:
            raise ValueError(f"Unknown role: {role}")
