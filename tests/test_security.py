"""
SecureEV-OTA: Security Module Tests

Tests for the Phase 2 security components:
- End-to-End Encryption (E2E)
- Denial-of-Service (DoS) Protection
"""

import pytest
import json
import time
from src.security import E2EEncryption, DoSProtection
from src.security.e2e_encryption import EncryptedPackage
from src.crypto.ecc_core import ECDHKeyExchange, ECCCore


class TestE2EEncryption:
    """Test suite for end-to-end encryption module."""
    
    def test_session_establishment(self):
        """Test derivation of matching session keys between two parties."""
        e2e = E2EEncryption()
        
        # Parties generate ephemeral keys
        alice_priv, alice_pub = e2e.generate_ephemeral_keypair()
        bob_priv, bob_pub = e2e.generate_ephemeral_keypair()
        
        # Derive keys
        alice_session = e2e.derive_session_key(alice_priv, bob_pub)
        bob_session = e2e.derive_session_key(bob_priv, alice_pub)
        
        assert alice_session.key == bob_session.key
        assert len(alice_session.key) == 32

    def test_encrypt_decrypt_payload(self):
        """Test basic encryption and decryption functionality."""
        e2e = E2EEncryption()
        alice_priv, alice_pub = e2e.generate_ephemeral_keypair()
        bob_priv, bob_pub = e2e.generate_ephemeral_keypair()
        
        data = b"Secret firmware update payload"
        
        # Alice encrypts for Bob
        package = e2e.encrypt(data, alice_priv, bob_pub)
        
        # Bob decrypts from Alice
        plaintext = e2e.decrypt(package, bob_priv)
        
        assert plaintext == data
        assert package.ciphertext != data

    def test_authenticated_metadata(self):
        """Test that associated metadata is authenticated but not encrypted."""
        e2e = E2EEncryption()
        alice_priv, alice_pub = e2e.generate_ephemeral_keypair()
        bob_priv, bob_pub = e2e.generate_ephemeral_keypair()
        
        data = b"Firmware"
        metadata = {"version": "1.0", "ecu": "primary"}
        assoc_data = json.dumps(metadata).encode()
        
        package = e2e.encrypt(data, alice_priv, bob_pub, assoc_data)
        
        # Decryption with correct metadata should succeed
        plaintext = e2e.decrypt(package, bob_priv, assoc_data)
        assert plaintext == data
        
        # Decryption with wrong/tampered metadata should fail
        wrong_metadata = {"version": "1.1", "ecu": "primary"}
        wrong_assoc = json.dumps(wrong_metadata).encode()
        
        with pytest.raises(Exception):
            e2e.decrypt(package, bob_priv, wrong_assoc)

    def test_package_serialization(self):
        """Test the serialization of encrypted packages."""
        e2e = E2EEncryption()
        alice_priv, alice_pub = e2e.generate_ephemeral_keypair()
        bob_priv, bob_pub = e2e.generate_ephemeral_keypair()
        
        data = b"Firmware Binary"
        package = e2e.encrypt(data, alice_priv, bob_pub)
        
        package_dict = package.to_dict()
        recovered_package = EncryptedPackage.from_dict(package_dict)
        
        decrypted_data = e2e.decrypt(recovered_package, bob_priv)
        assert decrypted_data == data


class TestDoSProtection:
    """Test suite for DoS protection module."""
    
    def test_rate_limiting_global(self):
        """Test that the global rate limiter kicks in."""
        # Low capacity for testing
        dos = DoSProtection(global_capacity=2, global_rate=1)
        
        assert dos.is_request_allowed("v1") is True
        assert dos.is_request_allowed("v2") is True
        # Third request should be blocked
        assert dos.is_request_allowed("v3") is False

    def test_rate_limiting_per_vehicle(self):
        """Test that per-vehicle limits are enforced independently."""
        dos = DoSProtection(per_vehicle_capacity=1, per_vehicle_rate=0.1)
        
        assert dos.is_request_allowed("v1") is True
        # Second request from v1 should be blocked
        assert dos.is_request_allowed("v1") is False
        # But v2 should still be allowed
        assert dos.is_request_allowed("v2") is True

    def test_blacklisting(self):
        """Test that repeated invalid requests result in blacklisting."""
        dos = DoSProtection()
        vehicle_id = "attacker_1"
        
        # Send 10 invalid requests
        for _ in range(10):
            dos.report_invalid_request(vehicle_id)
            
        # Vehicle should now be blacklisted
        assert dos.is_request_allowed(vehicle_id) is False
        
        # Even after time passes, blacklisting persists until reset
        dos.reset_vehicle(vehicle_id)
        assert dos.is_request_allowed(vehicle_id) is True

    def test_token_bucket_refill(self):
        """Test that tokens refill over time."""
        # Capacity 1, rate 10 per second
        dos = DoSProtection(per_vehicle_capacity=1, per_vehicle_rate=10)
        
        assert dos.is_request_allowed("v1") is True
        assert dos.is_request_allowed("v1") is False
        
        # Wait 0.2s, should have 2 new tokens
        time.sleep(0.2)
        assert dos.is_request_allowed("v1") is True
