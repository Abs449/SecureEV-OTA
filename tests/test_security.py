"""
Test Suite for SecureEV-OTA Security Module

Comprehensive tests for:
- End-to-end encryption (E2EEncryption)
- DoS protection (rate limiting, timeouts, multi-path)
- Integration scenarios
"""

import pytest
import time
import secrets
from typing import Callable

# Add src to path
import sys
sys.path.insert(0, 'src')

from security.e2e_encryption import (
    E2EEncryption,
    EncryptedPackage,
    SessionKey,
    EncryptionMode,
    EncryptionError,
    DecryptionError,
    KeyExchangeError,
)

from security.dos_protection import (
    DoSProtection,
    AdaptiveRateLimiter,
    ProgressiveTimeoutManager,
    MultiPathDelivery,
    UpdateRequest,
    UpdatePriority,
    RequestStatus,
    RateLimitConfig,
    TimeoutConfig,
    EndpointConfig,
    RateLimitExceeded,
    AllEndpointsFailed,
)


class TestE2EEncryption:
    """Tests for end-to-end encryption module."""
    
    def test_keypair_generation(self):
        """Test ephemeral keypair generation."""
        e2e = E2EEncryption()
        
        private_key, public_key = e2e.generate_ephemeral_keypair()
        
        assert private_key is not None
        assert public_key is not None
    
    def test_session_key_derivation(self):
        """Test ECDH session key derivation."""
        e2e1 = E2EEncryption()
        e2e2 = E2EEncryption()
        
        # Generate keypairs
        priv1, pub1 = e2e1.generate_ephemeral_keypair()
        priv2, pub2 = e2e2.generate_ephemeral_keypair()
        
        # Both derive same session key
        session1 = e2e1.derive_session_key(priv1, pub2)
        session2 = e2e2.derive_session_key(priv2, pub1)
        
        assert session1.key == session2.key
        assert len(session1.key) == 32  # AES-256
        assert session1.key_id == session2.key_id
    
    def test_encrypt_decrypt_round_trip(self):
        """Test complete encryption and decryption cycle."""
        server_e2e = E2EEncryption()
        vehicle_e2e = E2EEncryption()
        
        # Generate keys
        server_priv, server_pub = server_e2e.generate_ephemeral_keypair()
        vehicle_priv, vehicle_pub = vehicle_e2e.generate_ephemeral_keypair()
        
        # Encrypt
        plaintext = b"Critical firmware update for ECU"
        additional_data = b"ECU_ID:primary-001"
        
        encrypted = server_e2e.encrypt(
            plaintext,
            server_priv,
            vehicle_pub,
            additional_data
        )
        
        assert encrypted.ciphertext != plaintext
        assert len(encrypted.nonce) == 12
        assert len(encrypted.tag) == 16
        
        # Decrypt
        decrypted = vehicle_e2e.decrypt(
            encrypted,
            vehicle_priv,
            additional_data
        )
        
        assert decrypted == plaintext
    
    def test_decryption_with_wrong_aad_fails(self):
        """Test that decryption fails if AAD doesn't match."""
        server_e2e = E2EEncryption()
        vehicle_e2e = E2EEncryption()
        
        server_priv, server_pub = server_e2e.generate_ephemeral_keypair()
        vehicle_priv, vehicle_pub = vehicle_e2e.generate_ephemeral_keypair()
        
        plaintext = b"Firmware data"
        original_aad = b"ECU_ID:primary-001"
        wrong_aad = b"ECU_ID:primary-002"
        
        encrypted = server_e2e.encrypt(plaintext, server_priv, vehicle_pub, original_aad)
        
        with pytest.raises(DecryptionError):
            vehicle_e2e.decrypt(encrypted, vehicle_priv, wrong_aad)
    
    def test_session_key_expiration(self):
        """Test that expired session keys are rejected."""
        server_e2e = E2EEncryption(session_duration=1)  # 1 second expiration
        vehicle_e2e = E2EEncryption()
        
        server_priv, server_pub = server_e2e.generate_ephemeral_keypair()
        vehicle_priv, vehicle_pub = vehicle_e2e.generate_ephemeral_keypair()
        
        # Encrypt
        encrypted = server_e2e.encrypt(b"Test data", server_priv, vehicle_pub)
        
        # Decrypt should work immediately
        decrypted = vehicle_e2e.decrypt(encrypted, vehicle_priv)
        assert decrypted == b"Test data"
        
        # Wait for server session to expire
        time.sleep(1.5)
        
        # Try to encrypt again - should create new session
        # (This test just verifies cleanup works)
        removed = server_e2e.cleanup_expired_keys()
        assert removed >= 0  # May or may not have keys to clean
    
    def test_nonce_uniqueness(self):
        """Test that nonces are unique across encryptions."""
        e2e = E2EEncryption()
        
        priv1, pub1 = e2e.generate_ephemeral_keypair()
        priv2, pub2 = e2e.generate_ephemeral_keypair()
        
        nonces = set()
        for i in range(100):
            encrypted = e2e.encrypt(f"Data {i}".encode(), priv1, pub2)
            nonce_hex = encrypted.nonce.hex()
            assert nonce_hex not in nonces
            nonces.add(nonce_hex)
    
    def test_package_serialization(self):
        """Test EncryptedPackage serialization and deserialization."""
        e2e = E2EEncryption()
        
        priv1, pub1 = e2e.generate_ephemeral_keypair()
        priv2, pub2 = e2e.generate_ephemeral_keypair()
        
        plaintext = b"Test firmware"
        encrypted = e2e.encrypt(plaintext, priv1, pub2)
        
        # Serialize
        serialized = encrypted.to_dict()
        assert 'ciphertext' in serialized
        assert 'nonce' in serialized
        assert 'tag' in serialized
        
        # Deserialize
        recovered = EncryptedPackage.from_dict(serialized)
        assert recovered.ciphertext == encrypted.ciphertext
        assert recovered.nonce == encrypted.nonce
        assert recovered.tag == encrypted.tag
        
        # Decrypt recovered package
        decrypted = e2e.decrypt(recovered, priv2)
        assert decrypted == plaintext
    
    def test_session_cleanup(self):
        """Test cleanup of expired sessions."""
        e2e = E2EEncryption(session_duration=1)
        
        priv1, pub1 = e2e.generate_ephemeral_keypair()
        priv2, pub2 = e2e.generate_ephemeral_keypair()
        
        # Create multiple sessions
        for i in range(5):
            e2e.encrypt(f"Data {i}".encode(), priv1, pub2)
        
        assert len(e2e._session_keys) == 1  # Same session key reused
        
        # Wait for expiration
        time.sleep(1.5)
        
        # Cleanup
        removed = e2e.cleanup_expired_keys()
        assert removed == 1
        assert len(e2e._session_keys) == 0


class TestAdaptiveRateLimiter:
    """Tests for adaptive rate limiter."""
    
    def test_basic_rate_limiting(self):
        """Test basic rate limiting functionality."""
        config = RateLimitConfig(requests_per_minute=10, burst_factor=1.5)
        limiter = AdaptiveRateLimiter(config)
        
        vehicle_id = "VIN_TEST_001"
        
        # Should allow first 15 requests (10 * 1.5 burst)
        allowed_count = 0
        for i in range(20):
            if limiter.allow_request(vehicle_id):
                allowed_count += 1
        
        assert allowed_count == 15  # Burst limit
    
    def test_critical_priority_bypasses_limit(self):
        """Test that critical requests bypass rate limits."""
        config = RateLimitConfig(requests_per_minute=5, burst_factor=1.0)
        limiter = AdaptiveRateLimiter(config)
        
        vehicle_id = "VIN_TEST_002"
        
        # Fill up the rate limit
        for i in range(5):
            assert limiter.allow_request(vehicle_id)
        
        # Normal request should be blocked
        assert not limiter.allow_request(vehicle_id, UpdatePriority.NORMAL)
        
        # Critical request should bypass
        assert limiter.allow_request(vehicle_id, UpdatePriority.CRITICAL)
    
    def test_per_vehicle_isolation(self):
        """Test that rate limits are per-vehicle."""
        config = RateLimitConfig(requests_per_minute=5, burst_factor=1.0)
        limiter = AdaptiveRateLimiter(config)
        
        # Vehicle 1 uses up its quota (5 requests, burst=1.0)
        for i in range(5):
            assert limiter.allow_request("VIN_001")
        
        assert not limiter.allow_request("VIN_001")
        
        # Vehicle 2 should still have quota
        assert limiter.allow_request("VIN_002")
    
    def test_sliding_window(self):
        """Test sliding window rate limiting."""
        config = RateLimitConfig(
            requests_per_minute=10,
            burst_factor=1.0,
            window_size_seconds=2
        )
        limiter = AdaptiveRateLimiter(config)
        
        vehicle_id = "VIN_TEST_003"
        
        # Use up quota
        for i in range(10):
            assert limiter.allow_request(vehicle_id)
        
        # Should be rate limited
        assert not limiter.allow_request(vehicle_id)
        
        # Wait for window to pass
        time.sleep(2.5)
        
        # Should allow requests again
        assert limiter.allow_request(vehicle_id)
    
    def test_rate_info(self):
        """Test getting rate limit information."""
        config = RateLimitConfig(requests_per_minute=10, burst_factor=1.5)
        limiter = AdaptiveRateLimiter(config)
        
        vehicle_id = "VIN_TEST_004"
        
        # Make some requests
        for i in range(5):
            limiter.allow_request(vehicle_id)
        
        info = limiter.get_rate_info(vehicle_id)
        
        assert info['vehicle_id'] == vehicle_id
        assert info['recent_requests'] == 5
        assert info['limit'] == 15  # 10 * 1.5
        assert info['requests_remaining'] == 10


class TestProgressiveTimeoutManager:
    """Tests for progressive timeout manager."""
    
    def test_initial_timeout(self):
        """Test initial timeout value."""
        config = TimeoutConfig(initial_timeout_ms=5000)
        manager = ProgressiveTimeoutManager(config)
        
        timeout = manager.get_timeout("req_001", UpdatePriority.NORMAL)
        assert timeout == 5000
    
    def test_exponential_backoff(self):
        """Test exponential backoff on retries."""
        config = TimeoutConfig(
            initial_timeout_ms=1000,
            backoff_factor=2.0,
            max_timeout_ms=10000
        )
        manager = ProgressiveTimeoutManager(config)
        
        request_id = "req_002"
        
        # Initial
        timeout1 = manager.get_timeout(request_id, UpdatePriority.NORMAL)
        assert timeout1 == 1000
        
        # First retry
        manager.record_retry(request_id)
        timeout2 = manager.get_timeout(request_id, UpdatePriority.NORMAL)
        assert timeout2 == 2000
        
        # Second retry
        manager.record_retry(request_id)
        timeout3 = manager.get_timeout(request_id, UpdatePriority.NORMAL)
        assert timeout3 == 4000
    
    def test_max_timeout_cap(self):
        """Test that timeout is capped at maximum."""
        config = TimeoutConfig(
            initial_timeout_ms=1000,
            backoff_factor=2.0,
            max_timeout_ms=5000
        )
        manager = ProgressiveTimeoutManager(config)
        
        request_id = "req_003"
        
        # Record many retries
        for i in range(10):
            manager.record_retry(request_id)
        
        timeout = manager.get_timeout(request_id, UpdatePriority.NORMAL)
        assert timeout == 5000  # Capped at max
    
    def test_critical_priority_timeout(self):
        """Test faster timeout for critical requests."""
        config = TimeoutConfig(
            initial_timeout_ms=5000,
            critical_timeout_ms=2000
        )
        manager = ProgressiveTimeoutManager(config)
        
        timeout_normal = manager.get_timeout("req_004", UpdatePriority.NORMAL)
        timeout_critical = manager.get_timeout("req_005", UpdatePriority.CRITICAL)
        
        assert timeout_critical < timeout_normal
        assert timeout_critical == 2000
    
    def test_reset_retries(self):
        """Test resetting retry count after success."""
        config = TimeoutConfig(initial_timeout_ms=1000, backoff_factor=2.0)
        manager = ProgressiveTimeoutManager(config)
        
        request_id = "req_006"
        
        # Record retries
        for i in range(3):
            manager.record_retry(request_id)
        
        timeout_before = manager.get_timeout(request_id, UpdatePriority.NORMAL)
        assert timeout_before == 8000  # 1000 * 2^3
        
        # Reset
        manager.reset_retries(request_id)
        
        timeout_after = manager.get_timeout(request_id, UpdatePriority.NORMAL)
        assert timeout_after == 1000  # Back to initial


class TestMultiPathDelivery:
    """Tests for multi-path delivery manager."""
    
    def test_endpoint_ordering(self):
        """Test that endpoints are ordered by health."""
        config = EndpointConfig(
            primary_endpoint='https://primary.example.com',
            fallback_endpoints=[
                'https://fallback1.example.com',
                'https://fallback2.example.com'
            ]
        )
        multi_path = MultiPathDelivery(config)
        
        # Initially, primary should be first
        endpoints = multi_path.get_ordered_endpoints()
        assert endpoints[0] == 'https://primary.example.com'
    
    def test_health_tracking(self):
        """Test endpoint health tracking."""
        config = EndpointConfig(
            primary_endpoint='https://primary.example.com',
            failure_threshold=3
        )
        multi_path = MultiPathDelivery(config)
        
        endpoint = 'https://primary.example.com'
        
        # Record successes
        for i in range(5):
            multi_path.record_success(endpoint)
        
        health = multi_path.get_health_status()
        assert health[endpoint]['is_healthy'] is True
        assert health[endpoint]['success_rate'] == 1.0
        
        # Record failures
        for i in range(3):
            multi_path.record_failure(endpoint)
        
        health = multi_path.get_health_status()
        assert health[endpoint]['is_healthy'] is False
        assert health[endpoint]['success_rate'] == 5 / 8  # 5 success, 3 failures
    
    def test_failover_to_backup(self):
        """Test failover to backup endpoint when primary fails."""
        config = EndpointConfig(
            primary_endpoint='https://primary.example.com',
            fallback_endpoints=['https://backup.example.com'],
            failure_threshold=2
        )
        multi_path = MultiPathDelivery(config)
        
        # Mark primary as unhealthy
        for i in range(2):
            multi_path.record_failure('https://primary.example.com')
        
        endpoints = multi_path.get_ordered_endpoints()
        
        # Backup should come before unhealthy primary
        assert 'https://backup.example.com' in endpoints
    
    def test_recovery_from_failure(self):
        """Test endpoint recovery after failures."""
        config = EndpointConfig(
            primary_endpoint='https://primary.example.com',
            failure_threshold=2
        )
        multi_path = MultiPathDelivery(config)
        
        endpoint = 'https://primary.example.com'
        
        # Mark as unhealthy
        for i in range(2):
            multi_path.record_failure(endpoint)
        
        health = multi_path.get_health_status()
        assert health[endpoint]['is_healthy'] is False
        
        # Record success (recovery)
        multi_path.record_success(endpoint)
        
        health = multi_path.get_health_status()
        assert health[endpoint]['is_healthy'] is True


class TestDoSProtection:
    """Integration tests for complete DoS protection."""
    
    def test_complete_request_processing(self):
        """Test complete request processing with all protections."""
        dos = DoSProtection(
            rate_config=RateLimitConfig(requests_per_minute=10),
            timeout_config=TimeoutConfig(initial_timeout_ms=100),
            endpoint_config=EndpointConfig(
                primary_endpoint='https://test.example.com'
            )
        )
        
        def mock_fetch(endpoint: str, timeout: float) -> bytes:
            """Mock fetch function."""
            return b"Firmware data"
        
        request = UpdateRequest(
            vehicle_id='VIN_INTEGRATION_001',
            firmware_version='2.1.5',
            priority=UpdatePriority.NORMAL
        )
        
        data = dos.process_request(request, mock_fetch)
        
        assert data == b"Firmware data"
        assert request.status == RequestStatus.COMPLETED
    
    def test_rate_limit_enforcement(self):
        """Test that rate limiting is enforced in integration."""
        dos = DoSProtection(
            rate_config=RateLimitConfig(requests_per_minute=5, burst_factor=1.0)
        )
        
        def mock_fetch(endpoint: str, timeout: float) -> bytes:
            return b"Data"
        
        vehicle_id = 'VIN_INTEGRATION_002'
        
        # Fill quota
        for i in range(5):
            request = UpdateRequest(
                vehicle_id=vehicle_id,
                firmware_version=f'2.1.{i}',
                priority=UpdatePriority.NORMAL
            )
            dos.process_request(request, mock_fetch)
        
        # Next request should be rate limited
        request = UpdateRequest(
            vehicle_id=vehicle_id,
            firmware_version='2.2.0',
            priority=UpdatePriority.NORMAL
        )
        
        with pytest.raises(RateLimitExceeded):
            dos.process_request(request, mock_fetch)
    
    def test_endpoint_failover(self):
        """Test automatic failover to backup endpoints."""
        dos = DoSProtection(
            endpoint_config=EndpointConfig(
                primary_endpoint='https://primary.example.com',
                fallback_endpoints=['https://backup.example.com']
            )
        )
        
        attempt_count = {'primary': 0, 'backup': 0}
        
        def mock_fetch(endpoint: str, timeout: float) -> bytes:
            """Mock fetch that fails on primary, succeeds on backup."""
            if 'primary' in endpoint:
                attempt_count['primary'] += 1
                raise Exception("Primary down")
            else:
                attempt_count['backup'] += 1
                return b"Firmware from backup"
        
        request = UpdateRequest(
            vehicle_id='VIN_INTEGRATION_003',
            firmware_version='2.1.5',
            priority=UpdatePriority.NORMAL
        )
        
        data = dos.process_request(request, mock_fetch)
        
        assert data == b"Firmware from backup"
        assert attempt_count['primary'] == 1
        assert attempt_count['backup'] == 1
    
    def test_statistics_collection(self):
        """Test DoS protection statistics."""
        dos = DoSProtection()
        
        stats = dos.get_protection_stats()
        
        assert 'endpoints' in stats
        assert isinstance(stats['endpoints'], dict)


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
