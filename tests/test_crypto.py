"""
Test Suite for SecureEV-OTA Crypto Module

Comprehensive tests for:
- Core ECC operations (ECDSA, ECDH)
- Lightweight ECC implementation
- Batch ECDSA verification
- Hybrid PQC signatures
"""

import pytest
import hashlib
import time
from typing import List

# Import crypto modules
import sys
sys.path.insert(0, 'src')

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class TestECCCore:
    """Tests for core ECC operations."""
    
    def test_keypair_generation(self):
        """Test ECDSA key pair generation."""
        from crypto.ecc_core import ECCCore, ECCCurve
        
        ecc = ECCCore(ECCCurve.SECP256R1)
        keypair = ecc.generate_keypair()
        
        assert keypair.private_key is not None
        assert keypair.public_key is not None
        assert keypair.curve == ECCCurve.SECP256R1
        assert len(keypair.key_id) == 16  # 16 hex chars
    
    def test_sign_and_verify(self):
        """Test ECDSA signing and verification."""
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        keypair = ecc.generate_keypair()
        
        message = b"Test firmware update"
        signature = ecc.sign(keypair.private_key, message, keypair.key_id)
        
        assert signature.signature is not None
        assert signature.key_id == keypair.key_id
        assert "ecdsa" in signature.algorithm
        
        # Verify
        is_valid = ecc.verify_signature(keypair.public_key, signature, message)
        assert is_valid is True
    
    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected."""
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        keypair = ecc.generate_keypair()
        
        message = b"Original message"
        tampered_message = b"Tampered message"
        
        signature = ecc.sign(keypair.private_key, message, keypair.key_id)
        
        # Verify with wrong message
        is_valid = ecc.verify_signature(keypair.public_key, signature, tampered_message)
        assert is_valid is False
    
    def test_different_keys_rejected(self):
        """Test that signature with different key is rejected."""
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        keypair1 = ecc.generate_keypair()
        keypair2 = ecc.generate_keypair()
        
        message = b"Test message"
        signature = ecc.sign(keypair1.private_key, message, keypair1.key_id)
        
        # Verify with wrong key
        is_valid = ecc.verify_signature(keypair2.public_key, signature, message)
        assert is_valid is False


class TestECDHKeyExchange:
    """Tests for ECDH key exchange."""
    
    def test_shared_secret_derivation(self):
        """Test that both parties derive same shared secret."""
        from crypto.ecc_core import ECDHKeyExchange
        
        ecdh = ECDHKeyExchange()
        
        # Vehicle and server key pairs
        vehicle_keypair = ecdh.generate_ephemeral_keypair()
        server_keypair = ecdh.generate_ephemeral_keypair()
        
        # Both derive session key
        vehicle_key = ecdh.derive_session_key(
            vehicle_keypair.private_key,
            server_keypair.public_key
        )
        server_key = ecdh.derive_session_key(
            server_keypair.private_key,
            vehicle_keypair.public_key
        )
        
        assert vehicle_key == server_key
        assert len(vehicle_key) == 32  # AES-256 key
    
    def test_different_sessions_different_keys(self):
        """Test that different sessions produce different keys."""
        from crypto.ecc_core import ECDHKeyExchange
        
        ecdh = ECDHKeyExchange()
        
        # Session 1
        v1 = ecdh.generate_ephemeral_keypair()
        s1 = ecdh.generate_ephemeral_keypair()
        key1 = ecdh.derive_session_key(v1.private_key, s1.public_key)
        
        # Session 2
        v2 = ecdh.generate_ephemeral_keypair()
        s2 = ecdh.generate_ephemeral_keypair()
        key2 = ecdh.derive_session_key(v2.private_key, s2.public_key)
        
        assert key1 != key2
    
    def test_nonce_generation(self):
        """Test cryptographic nonce generation."""
        from crypto.ecc_core import ECDHKeyExchange
        
        ecdh = ECDHKeyExchange()
        
        nonce1 = ecdh.generate_nonce()
        nonce2 = ecdh.generate_nonce()
        
        assert len(nonce1) == 12  # Default AES-GCM nonce size
        assert nonce1 != nonce2


class TestLightweightECC:
    """Tests for memory-optimized ECC implementation."""
    
    def test_point_compression(self):
        """Test point compression and decompression."""
        from crypto.lightweight_ecc import Point, P256
        
        # Generator point
        G = Point.generator()
        
        # Compress
        compressed = G.to_bytes(compressed=True)
        uncompressed = G.to_bytes(compressed=False)
        
        assert len(compressed) == 33  # 1 + 32 bytes
        assert len(uncompressed) == 65  # 1 + 32 + 32 bytes
        
        # Decompress
        recovered = Point.from_bytes(compressed)
        assert recovered == G
    
    def test_scalar_multiplication(self):
        """Test scalar multiplication."""
        from crypto.lightweight_ecc import LightweightECC, Point
        
        ecc = LightweightECC(precompute=False)
        G = Point.generator()
        
        # k*G for known k
        k = 12345
        result = ecc.scalar_multiply(k, G)
        
        assert not result.is_infinity
        assert result.x is not None
        assert result.y is not None
    
    def test_signing_and_verification(self):
        """Test lightweight ECDSA sign and verify."""
        from crypto.lightweight_ecc import LightweightECC, P256
        import secrets
        
        ecc = LightweightECC(precompute=True)
        
        # Generate key pair
        private_key = secrets.randbelow(P256.N - 1) + 1
        public_key = ecc.scalar_multiply_generator(private_key)
        
        # Sign
        message = b"Firmware update for ECU"
        message_hash = hashlib.sha256(message).digest()
        signature = ecc.ecdsa_sign(private_key, message_hash)
        
        assert len(signature) == 2  # (r, s) tuple
        
        # Verify
        is_valid = ecc.ecdsa_verify(public_key, message_hash, signature)
        assert is_valid is True
    
    def test_shamirs_trick(self):
        """Test Shamir's trick for aP + bQ."""
        from crypto.lightweight_ecc import LightweightECC, Point
        
        ecc = LightweightECC(precompute=True)
        G = Point.generator()
        
        # Compute 5*G and 7*G separately
        k1, k2 = 5, 7
        p1 = ecc.scalar_multiply(k1, G)
        p2 = ecc.scalar_multiply(k2, G)
        
        # Compute (2*P1 + 3*P2) using Shamir's trick
        a, b = 2, 3
        result_shamir = ecc.shamirs_trick(a, p1, b, p2)
        
        # Compute the same manually
        ap1 = ecc.scalar_multiply(a, p1)
        bp2 = ecc.scalar_multiply(b, p2)
        result_manual = ecc.point_add(ap1, bp2)
        
        assert result_shamir == result_manual
    
    def test_memory_estimate(self):
        """Test memory usage estimation."""
        from crypto.lightweight_ecc import estimate_memory_usage
        
        mem_no_precomp = estimate_memory_usage(False)
        mem_with_precomp = estimate_memory_usage(True)
        
        assert mem_no_precomp['total'] < mem_with_precomp['total']
        assert mem_no_precomp['total'] < 10000  # < 10KB without precompute


class TestBatchVerification:
    """Tests for batch ECDSA verification."""
    
    def test_batch_all_valid(self):
        """Test batch verification with all valid signatures."""
        from crypto.batch_verifier import (
            BatchECDSAVerifier, SignatureItem, BatchVerificationMode
        )
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        verifier = BatchECDSAVerifier(mode=BatchVerificationMode.AGGREGATE)
        
        # Create batch of valid signatures
        items = []
        for i in range(8):
            keypair = ecc.generate_keypair()
            message = f"Update package {i}".encode()
            signature = keypair.private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            items.append(SignatureItem(
                public_key=keypair.public_key,
                message=message,
                signature=signature
            ))
        
        result = verifier.verify_batch(items)
        
        assert result.all_valid is True
        assert result.count == 8
    
    def test_batch_with_invalid(self):
        """Test batch verification with one invalid signature."""
        from crypto.batch_verifier import (
            BatchECDSAVerifier, SignatureItem, BatchVerificationMode
        )
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        verifier = BatchECDSAVerifier(mode=BatchVerificationMode.INDIVIDUAL)
        
        items = []
        for i in range(5):
            keypair = ecc.generate_keypair()
            message = f"Update {i}".encode()
            signature = keypair.private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            # Corrupt one signature
            if i == 2:
                signature = b'\x00' * len(signature)
            
            items.append(SignatureItem(
                public_key=keypair.public_key,
                message=message,
                signature=signature
            ))
        
        result = verifier.verify_batch(items)
        
        assert result.all_valid is False
        assert 2 in result.invalid_indices
    
    def test_small_batch_fallback(self):
        """Test that small batches use individual verification."""
        from crypto.batch_verifier import BatchECDSAVerifier, SignatureItem
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        verifier = BatchECDSAVerifier(min_batch_size=4)
        
        # Create batch smaller than threshold
        items = []
        for i in range(2):
            keypair = ecc.generate_keypair()
            message = f"Small batch {i}".encode()
            signature = keypair.private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            items.append(SignatureItem(
                public_key=keypair.public_key,
                message=message,
                signature=signature
            ))
        
        result = verifier.verify_batch(items)
        
        assert result.all_valid is True
        assert result.count == 2


class TestHybridPQC:
    """Tests for hybrid post-quantum cryptography."""
    
    def test_keypair_generation(self):
        """Test hybrid keypair generation."""
        from crypto.hybrid_pqc import HybridCrypto, PQCAlgorithm
        
        hybrid = HybridCrypto(pqc_algorithm=PQCAlgorithm.ML_DSA_65)
        keypair = hybrid.generate_keypair()
        
        assert keypair.ecdsa_private_key is not None
        assert keypair.ecdsa_public_key is not None
        assert keypair.pqc_private_key is not None
        assert keypair.pqc_public_key is not None
        assert len(keypair.key_id) == 16
    
    def test_hybrid_sign_verify(self):
        """Test hybrid signing and verification."""
        from crypto.hybrid_pqc import HybridCrypto, HybridMode
        
        hybrid = HybridCrypto(mode=HybridMode.PARALLEL)
        keypair = hybrid.generate_keypair()
        
        message = b"Critical security update"
        signature = hybrid.sign(keypair, message)
        
        assert signature.ecdsa_signature is not None
        assert signature.pqc_signature is not None
        
        is_valid = hybrid.verify(keypair, message, signature)
        assert is_valid is True
    
    def test_classical_only_mode(self):
        """Test classical-only verification mode."""
        from crypto.hybrid_pqc import HybridCrypto, HybridMode
        
        hybrid = HybridCrypto(mode=HybridMode.CLASSICAL_ONLY)
        keypair = hybrid.generate_keypair()
        
        message = b"Legacy compatible update"
        signature = hybrid.sign(keypair, message)
        
        is_valid = hybrid.verify(keypair, message, signature)
        assert is_valid is True
    
    def test_ecdsa_backward_compatibility(self):
        """Test ECDSA-only verification for backward compatibility."""
        from crypto.hybrid_pqc import HybridCrypto
        
        hybrid = HybridCrypto()
        keypair = hybrid.generate_keypair()
        
        message = b"Update for legacy vehicle"
        signature = hybrid.sign(keypair, message)
        
        # Verify using only ECDSA
        is_valid = hybrid.verify_ecdsa_only(
            keypair.ecdsa_public_key,
            message,
            signature
        )
        assert is_valid is True
    
    def test_signature_serialization(self):
        """Test hybrid signature serialization."""
        from crypto.hybrid_pqc import HybridCrypto, HybridSignature
        
        hybrid = HybridCrypto()
        keypair = hybrid.generate_keypair()
        
        message = b"Test message"
        signature = hybrid.sign(keypair, message)
        
        # Serialize
        serialized = signature.to_bytes()
        assert len(serialized) > 0
        
        # Deserialize
        recovered = HybridSignature.from_bytes(serialized)
        assert recovered.ecdsa_signature == signature.ecdsa_signature
        assert recovered.pqc_signature == signature.pqc_signature
    
    def test_signature_size_analysis(self):
        """Test signature size analysis."""
        from crypto.hybrid_pqc import (
            HybridCrypto, HybridSignatureAnalyzer, PQCAlgorithm
        )
        
        hybrid = HybridCrypto(pqc_algorithm=PQCAlgorithm.ML_DSA_65)
        keypair = hybrid.generate_keypair()
        
        message = b"Test message"
        signature = hybrid.sign(keypair, message)
        
        analysis = HybridSignatureAnalyzer.analyze_signature_size(signature)
        
        assert 'ecdsa_bytes' in analysis
        assert 'pqc_bytes' in analysis
        assert 'total_bytes' in analysis
        assert analysis['total_bytes'] == analysis['ecdsa_bytes'] + analysis['pqc_bytes']


class TestPerformance:
    """Performance benchmarks."""
    
    def test_signing_performance(self):
        """Benchmark ECDSA signing performance."""
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        keypair = ecc.generate_keypair()
        message = b"Performance test message"
        
        iterations = 100
        start = time.perf_counter()
        
        for _ in range(iterations):
            ecc.sign(keypair.private_key, message, keypair.key_id)
        
        elapsed = time.perf_counter() - start
        per_sign = (elapsed / iterations) * 1000
        
        print(f"\nECDSA signing: {per_sign:.2f}ms per operation")
        assert per_sign < 50  # Should be < 50ms
    
    def test_verification_performance(self):
        """Benchmark ECDSA verification performance."""
        from crypto.ecc_core import ECCCore
        
        ecc = ECCCore()
        keypair = ecc.generate_keypair()
        message = b"Performance test message"
        signature = ecc.sign(keypair.private_key, message, keypair.key_id)
        
        iterations = 100
        start = time.perf_counter()
        
        for _ in range(iterations):
            ecc.verify_signature(keypair.public_key, signature, message)
        
        elapsed = time.perf_counter() - start
        per_verify = (elapsed / iterations) * 1000
        
        print(f"ECDSA verification: {per_verify:.2f}ms per operation")
        assert per_verify < 50  # Should be < 50ms


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
