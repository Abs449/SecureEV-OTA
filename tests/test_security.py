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
from src.crypto.ecc_core import ECDHKeyExchange, ECCCore


class TestE2EEncryption:
    """Test suite for end-to-end encryption module."""
    
    def test_session_establishment(self):
        """Test derivation of matching session keys between two parties."""
        e2e = E2EEncryption()
        ecdh = ECDHKeyExchange()
        
        # Parties generate ephemeral keys
        alice_kp = ecdh.generate_ephemeral_keypair()
        bob_kp = ecdh.generate_ephemeral_keypair()
        
        # Derive keys
        alice_session = e2e.establish_session_key(alice_kp.private_key, bob_kp.public_key)
        bob_session = e2e.establish_session_key(bob_kp.private_key, alice_kp.public_key)
        
        assert alice_session == bob_session
        assert len(alice_session) == 32

    def test_encrypt_decrypt_payload(self):
        """Test basic encryption and decryption functionality."""
        e2e = E2EEncryption()
        session_key = b"0" * 32
        data = b"Secret firmware update payload"
        
        nonce, ciphertext = e2e.encrypt_payload(data, session_key)
        plaintext = e2e.decrypt_payload(ciphertext, nonce, session_key)
        
        assert plaintext == data
        assert ciphertext != data

    def test_authenticated_metadata(self):
        """Test that associated metadata is authenticated but not encrypted."""
        e2e = E2EEncryption()
        session_key = b"1" * 32
        data = b"Firmware"
        metadata = {"version": "1.0", "ecu": "primary"}
        
        assoc_data = json.dumps(metadata).encode()
        nonce, ciphertext = e2e.encrypt_payload(data, session_key, assoc_data)
        
        # Decryption with correct metadata should succeed
        plaintext = e2e.decrypt_payload(ciphertext, nonce, session_key, assoc_data)
        assert plaintext == data
        
        # Decryption with wrong/tampered metadata should fail
        wrong_metadata = {"version": "1.1", "ecu": "primary"}
        wrong_assoc = json.dumps(wrong_metadata).encode()
        
        with pytest.raises(Exception):
            e2e.decrypt_payload(ciphertext, nonce, session_key, wrong_assoc)

    def test_package_and_unpack(self):
        """Test the high-level packaging and unpacking logic."""
        e2e = E2EEncryption()
        session_key = b"2" * 32
        data = b"Firmware Binary"
        metadata = {"type": "critical", "checksum": "abc"}
        
        package = e2e.package_encrypted_update(data, session_key, metadata)
        decrypted_data, recovered_metadata = e2e.unpack_encrypted_update(package, session_key)
        
        assert decrypted_data == data
        assert recovered_metadata == metadata


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
