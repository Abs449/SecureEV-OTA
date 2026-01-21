"""
SecureEV-OTA: Uptane Protocol Tests

Tests for the Phase 3 protocol components:
- Metadata creation and serialization
- Signing and structure validation
"""

import pytest
import json
from datetime import datetime, timedelta

from src.uptane import RootMetadata, TargetsMetadata, SnapshotMetadata, TimestampMetadata
from src.uptane.manager import MetadataManager, MetadataVerificationError
from src.crypto.ecc_core import ECCCore, ECCCurve

class TestMetadataStructures:
    """Test suite for Uptane metadata classes."""
    
    @pytest.fixture
    def ecc(self):
        return ECCCore()
        
    @pytest.fixture
    def keypair(self, ecc):
        return ecc.generate_keypair()

    def test_root_metadata_creation(self, ecc, keypair):
        """Test creating and signing Root metadata."""
        # 1. Create Root
        expires = (datetime.now() + timedelta(days=365)).isoformat()
        root = RootMetadata(expires=expires, version=1)
        
        # 2. Add Trusted Keys
        root.add_key(keypair)
        
        # 3. Define Roles
        root.add_role("root", threshold=1, key_ids=[keypair.key_id])
        root.add_role("targets", threshold=1, key_ids=[keypair.key_id])
        
        # 4. Sign
        root.sign(keypair, ecc)
        
        # 5. Verify Structure
        data = root.to_dict()
        assert data["signed"]["_type"] == "root"
        assert data["signed"]["version"] == 1
        assert len(data["signatures"]) == 1
        assert data["signed"]["roles"]["root"]["threshold"] == 1
        assert keypair.key_id in data["signed"]["keys"]

    def test_targets_metadata(self, ecc, keypair):
        """Test Target metadata with firmware images."""
        expires = (datetime.now() + timedelta(days=30)).isoformat()
        targets = TargetsMetadata(expires=expires, version=1)
        
        targets.add_target(
            filename="firmware_v1.bin",
            file_hash="dummy_hash_123",
            length=1024,
            hardware_id="ecu-primary"
        )
        
        targets.sign(keypair, ecc)
        data = targets.to_dict()
        
        assert "firmware_v1.bin" in data["signed"]["targets"]
        assert data["signed"]["targets"]["firmware_v1.bin"]["length"] == 1024

    def test_snapshot_metadata(self, ecc, keypair):
        """Test Snapshot metadata linking to other files."""
        expires = (datetime.now() + timedelta(days=7)).isoformat()
        snapshot = SnapshotMetadata(expires=expires, version=1)
        
        snapshot.add_metadata_version("targets.json", 5)
        snapshot.add_metadata_version("root.json", 2)
        
        snapshot.sign(keypair, ecc)
        data = snapshot.to_dict()
        
        assert data["signed"]["meta"]["targets.json"]["version"] == 5
        assert data["signed"]["meta"]["root.json"]["version"] == 2

    def test_kanonical_serialization(self, ecc, keypair):
        """Test that signing uses canonical JSON (sorted keys)."""
        root = RootMetadata(expires="2026-01-01T00:00:00", version=1)
        root.sign(keypair, ecc)
        
        # Create a manual signature of the same data
        canonical_bytes = json.dumps({
            "_type": "root",
            "expires": "2026-01-01T00:00:00",
            "keys": {},
            "roles": {},
            "version": 1
        }, sort_keys=True).encode()
        
        sig = root.signatures[0]
        # Verify the signature against the canonical bytes
        assert ecc.verify(keypair.public_key, bytes.fromhex(sig["signature"]), canonical_bytes)


class TestMetadataVerification:
    """Test suite for MetadataManager verification logic."""
    
    @pytest.fixture
    def ecc(self):
        return ECCCore()
        
    @pytest.fixture
    def keypair(self, ecc):
        return ecc.generate_keypair()
        
    @pytest.fixture
    def root_data(self, ecc, keypair):
        """Create a signed Root object for testing."""
        root = RootMetadata(expires=(datetime.now() + timedelta(days=1)).isoformat(), version=1)
        root.add_key(keypair)
        root.add_role("root", 1, [keypair.key_id])
        root.sign(keypair, ecc)
        return root

    def test_verify_valid_signature(self, ecc, keypair, root_data):
        """Test verifying signature with trusted key."""
        manager = MetadataManager(ecc)
        
        # Determine the key structure
        # (simulating loading trusted keys from previous root)
        manager.trusted_keys[keypair.key_id] = keypair.public_key
        
        # Serialize and verify
        json_data = json.dumps(root_data.to_dict())
        obj = manager.verify_metadata(json_data, "root")
        
        assert isinstance(obj, RootMetadata)
        assert obj.version == 1

    def test_verify_expired_metadata(self, ecc, keypair):
        """Test rejection of expired metadata."""
        manager = MetadataManager(ecc)
        manager.trusted_keys[keypair.key_id] = keypair.public_key
        
        # Create expired root
        root = RootMetadata(expires=(datetime.now() - timedelta(days=1)).isoformat(), version=1)
        root.sign(keypair, ecc)
        
        json_data = json.dumps(root.to_dict())
        
        with pytest.raises(MetadataVerificationError, match="expired"):
            manager.verify_metadata(json_data, "root")

    def test_verify_invalid_signature(self, ecc, keypair, root_data):
        """Test rejection of invalid signature."""
        manager = MetadataManager(ecc)
        manager.trusted_keys[keypair.key_id] = keypair.public_key
        
        data_dict = root_data.to_dict()
        # Tamper with the signature
        data_dict["signatures"][0]["signature"] = "deadbeef" * 16
        
        with pytest.raises(Exception): # OpenSSL/crypto might raise generic error on bad hex
             manager.verify_metadata(json.dumps(data_dict), "root")

    def test_verify_tampered_content(self, ecc, keypair, root_data):
        """Test rejection when content does not match signature."""
        manager = MetadataManager(ecc)
        manager.trusted_keys[keypair.key_id] = keypair.public_key
        
        data_dict = root_data.to_dict()
        # Tamper with the version number
        data_dict["signed"]["version"] = 999
        
        with pytest.raises(MetadataVerificationError, match="No valid signatures"):
             manager.verify_metadata(json.dumps(data_dict), "root")
