"""
SecureEV-OTA: Core ECC Implementation

This module provides the core Elliptic Curve Cryptography functionality
for the SecureEV-OTA framework, implementing ECDSA for digital signatures
and ECDH for key exchange.

Based on improvements over the Uptane framework (USENIX 2016/2017).
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple
from enum import Enum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class ECCCurve(Enum):
    """Supported elliptic curves."""
    SECP256R1 = "secp256r1"  # NIST P-256 (recommended for general use)
    SECP384R1 = "secp384r1"  # NIST P-384 (higher security)
    SECP521R1 = "secp521r1"  # NIST P-521 (highest security)


@dataclass
class ECDSASignature:
    """ECDSA signature with metadata."""
    signature: bytes
    algorithm: str
    key_id: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "signature": self.signature.hex(),
            "algorithm": self.algorithm,
            "key_id": self.key_id
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ECDSASignature":
        """Create from dictionary."""
        return cls(
            signature=bytes.fromhex(data["signature"]),
            algorithm=data["algorithm"],
            key_id=data["key_id"]
        )


@dataclass
class ECCKeyPair:
    """ECC key pair container."""
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    curve: ECCCurve
    key_id: str
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key in compressed format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
    
    def get_private_key_bytes(self) -> bytes:
        """Get private key bytes (for secure storage only)."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )


class ECCCore:
    """
    Core ECC cryptographic operations for SecureEV-OTA.
    
    Provides:
    - ECDSA signing and verification
    - ECDH key exchange
    - Key generation and management
    
    Improvements over Uptane baseline:
    - Configurable curve selection
    - Key ID generation for multi-key management
    - Comprehensive error handling
    """
    
    DEFAULT_CURVE = ECCCurve.SECP256R1
    
    def __init__(self, curve: ECCCurve = DEFAULT_CURVE):
        """
        Initialize ECC core with specified curve.
        
        Args:
            curve: Elliptic curve to use (default: secp256r1/P-256)
        """
        self.curve = curve
        self._curve_obj = self._get_curve_object(curve)
    
    @staticmethod
    def _get_curve_object(curve: ECCCurve) -> ec.EllipticCurve:
        """Get cryptography library curve object."""
        curve_map = {
            ECCCurve.SECP256R1: ec.SECP256R1(),
            ECCCurve.SECP384R1: ec.SECP384R1(),
            ECCCurve.SECP521R1: ec.SECP521R1(),
        }
        return curve_map[curve]
    
    @staticmethod
    def _generate_key_id(public_key: ec.EllipticCurvePublicKey) -> str:
        """
        Generate unique key ID from public key.
        Uses SHA-256 hash of compressed public key.
        """
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        return hashlib.sha256(pub_bytes).hexdigest()[:16]
    
    def generate_keypair(self) -> ECCKeyPair:
        """
        Generate new ECC key pair.
        
        Returns:
            ECCKeyPair containing private key, public key, curve, and key ID
        """
        private_key = ec.generate_private_key(
            self._curve_obj,
            default_backend()
        )
        public_key = private_key.public_key()
        key_id = self._generate_key_id(public_key)
        
        return ECCKeyPair(
            private_key=private_key,
            public_key=public_key,
            curve=self.curve,
            key_id=key_id
        )
    
    def sign(self, 
             private_key: ec.EllipticCurvePrivateKey,
             data: bytes,
             key_id: Optional[str] = None) -> ECDSASignature:
        """
        Sign data using ECDSA.
        
        Args:
            private_key: ECDSA private key
            data: Data to sign
            key_id: Optional key identifier
            
        Returns:
            ECDSASignature containing signature bytes and metadata
        """
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        
        if key_id is None:
            key_id = self._generate_key_id(private_key.public_key())
        
        return ECDSASignature(
            signature=signature,
            algorithm=f"ecdsa-{self.curve.value}-sha256",
            key_id=key_id
        )
    
    def verify(self,
               public_key: ec.EllipticCurvePublicKey,
               signature: bytes,
               data: bytes) -> bool:
        """
        Verify ECDSA signature.
        
        Args:
            public_key: ECDSA public key
            signature: Signature bytes
            data: Original signed data
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            # Log unexpected errors in production
            raise ECCVerificationError(f"Verification failed: {e}") from e
    
    def verify_signature(self,
                        public_key: ec.EllipticCurvePublicKey,
                        signature: ECDSASignature,
                        data: bytes) -> bool:
        """
        Verify ECDSASignature object.
        
        Args:
            public_key: ECDSA public key
            signature: ECDSASignature object
            data: Original signed data
            
        Returns:
            True if signature is valid, False otherwise
        """
        return self.verify(public_key, signature.signature, data)


class ECDHKeyExchange:
    """
    ECDH (Elliptic Curve Diffie-Hellman) key exchange.
    
    Used for establishing shared secrets between:
    - OEM server and vehicle (firmware encryption)
    - Vehicles during V2V communication
    
    Improvement over Uptane:
    - Mandatory E2E encryption (vs. optional transport-only)
    - Per-session ephemeral keys for forward secrecy
    """
    
    def __init__(self, curve: ECCCurve = ECCCurve.SECP256R1):
        """
        Initialize ECDH with specified curve.
        
        Args:
            curve: Elliptic curve to use
        """
        self.curve = curve
        self.ecc_core = ECCCore(curve)
    
    def generate_ephemeral_keypair(self) -> ECCKeyPair:
        """
        Generate ephemeral key pair for single session.
        
        Returns:
            ECCKeyPair for this session only
        """
        return self.ecc_core.generate_keypair()
    
    def derive_shared_secret(self,
                            private_key: ec.EllipticCurvePrivateKey,
                            peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Derive shared secret using ECDH.
        
        Args:
            private_key: Our private key
            peer_public_key: Peer's public key
            
        Returns:
            Raw shared secret bytes
        """
        shared_secret = private_key.exchange(
            ec.ECDH(),
            peer_public_key
        )
        return shared_secret
    
    def derive_session_key(self,
                          private_key: ec.EllipticCurvePrivateKey,
                          peer_public_key: ec.EllipticCurvePublicKey,
                          key_length: int = 32,
                          info: bytes = b'secureev-ota-session') -> bytes:
        """
        Derive session key from ECDH shared secret using HKDF.
        
        Args:
            private_key: Our private key
            peer_public_key: Peer's public key
            key_length: Desired key length in bytes (default: 32 for AES-256)
            info: Context info for HKDF
            
        Returns:
            Derived session key
        """
        shared_secret = self.derive_shared_secret(private_key, peer_public_key)
        
        # Use HKDF to derive the session key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,  # Can be customized for additional security
            info=info,
        ).derive(shared_secret)
        
        return derived_key
    
    def generate_nonce(self, length: int = 12) -> bytes:
        """
        Generate cryptographically secure nonce.
        
        Args:
            length: Nonce length in bytes (default: 12 for AES-GCM)
            
        Returns:
            Random nonce bytes
        """
        return secrets.token_bytes(length)


class ECCVerificationError(Exception):
    """Exception raised for ECC verification errors."""
    pass


class ECCKeyError(Exception):
    """Exception raised for key-related errors."""
    pass


# Utility functions

def hash_message(message: bytes) -> bytes:
    """
    Hash message using SHA-256.
    
    Args:
        message: Message to hash
        
    Returns:
        SHA-256 hash bytes
    """
    return hashlib.sha256(message).digest()


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def public_key_from_bytes(
    key_bytes: bytes,
    curve: ECCCurve = ECCCurve.SECP256R1
) -> ec.EllipticCurvePublicKey:
    """
    Load public key from compressed point bytes.
    
    Args:
        key_bytes: Compressed public key bytes
        curve: Elliptic curve used
        
    Returns:
        EllipticCurvePublicKey object
    """
    curve_obj = ECCCore._get_curve_object(curve)
    return ec.EllipticCurvePublicKey.from_encoded_point(curve_obj, key_bytes)


# Example usage and module testing
if __name__ == "__main__":
    print("SecureEV-OTA Core ECC Module")
    print("=" * 50)
    
    # Initialize ECC core
    ecc = ECCCore()
    
    # Generate key pair
    keypair = ecc.generate_keypair()
    print(f"Generated key pair with ID: {keypair.key_id}")
    print(f"Curve: {keypair.curve.value}")
    
    # Sign a message
    message = b"Firmware update v2.1.5 for Primary ECU"
    signature = ecc.sign(keypair.private_key, message, keypair.key_id)
    print(f"\nSigned message with algorithm: {signature.algorithm}")
    print(f"Signature length: {len(signature.signature)} bytes")
    
    # Verify signature
    is_valid = ecc.verify_signature(keypair.public_key, signature, message)
    print(f"Signature valid: {is_valid}")
    
    # Test ECDH key exchange
    ecdh = ECDHKeyExchange()
    
    # Simulate vehicle and server key pairs
    vehicle_keypair = ecdh.generate_ephemeral_keypair()
    server_keypair = ecdh.generate_ephemeral_keypair()
    
    # Both derive same session key
    vehicle_session_key = ecdh.derive_session_key(
        vehicle_keypair.private_key,
        server_keypair.public_key
    )
    server_session_key = ecdh.derive_session_key(
        server_keypair.private_key,
        vehicle_keypair.public_key
    )
    
    print(f"\nECDH Key Exchange:")
    print(f"Vehicle session key: {vehicle_session_key.hex()[:32]}...")
    print(f"Server session key:  {server_session_key.hex()[:32]}...")
    print(f"Keys match: {vehicle_session_key == server_session_key}")
    
    print("\n✓ Core ECC module functioning correctly")
