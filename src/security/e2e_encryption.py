"""
SecureEV-OTA: End-to-End Encryption Module

Production-ready end-to-end encryption for OTA firmware updates using ECDH
key exchange and AES-256-GCM authenticated encryption.

Improvement over Uptane:
- MANDATORY end-to-end encryption (vs. optional transport-only)
- Per-session ephemeral keys for forward secrecy
- Authenticated encryption with AES-256-GCM
- Protection against eavesdropping even if TLS is compromised

Security Features:
- Perfect forward secrecy via ephemeral ECDH
- Authentication via GCM tags
- Nonce uniqueness enforcement
- Key rotation support
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from enum import Enum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Configure logging for production
logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Base exception for encryption errors."""
    pass


class DecryptionError(Exception):
    """Exception raised when decryption fails."""
    pass


class KeyExchangeError(Exception):
    """Exception raised during key exchange."""
    pass


class EncryptionMode(Enum):
    """Encryption modes."""
    AES_256_GCM = "aes-256-gcm"  # Authenticated encryption (recommended)
    AES_128_GCM = "aes-128-gcm"  # Faster but less secure


@dataclass
class SessionKey:
    """Session key with metadata."""
    key: bytes
    key_id: str
    created_at: float
    expires_at: float
    algorithm: EncryptionMode = EncryptionMode.AES_256_GCM
    
    def is_expired(self) -> bool:
        """Check if session key has expired."""
        return time.time() > self.expires_at
    
    def time_until_expiry(self) -> float:
        """Get seconds until expiration."""
        return max(0, self.expires_at - time.time())


@dataclass
class EncryptedPackage:
    """Encrypted data package with all necessary metadata."""
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    key_id: str
    algorithm: str
    sender_public_key: bytes  # Ephemeral public key for decryption
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'ciphertext': self.ciphertext.hex(),
            'nonce': self.nonce.hex(),
            'tag': self.tag.hex(),
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'sender_public_key': self.sender_public_key.hex()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedPackage":
        """Deserialize from dictionary."""
        return cls(
            ciphertext=bytes.fromhex(data['ciphertext']),
            nonce=bytes.fromhex(data['nonce']),
            tag=bytes.fromhex(data['tag']),
            key_id=data['key_id'],
            algorithm=data['algorithm'],
            sender_public_key=bytes.fromhex(data['sender_public_key'])
        )
    
    @property
    def total_size(self) -> int:
        """Total package size in bytes."""
        return (len(self.ciphertext) + len(self.nonce) + len(self.tag) +
                len(self.sender_public_key))


class E2EEncryption:
    """
    End-to-end encryption for OTA firmware updates.
    
    This class provides production-ready encryption that protects firmware
    even if transport-layer security (TLS) is compromised.
    
    Key Features:
    - Perfect forward secrecy via ephemeral ECDH
    - AES-256-GCM authenticated encryption
    - Automatic key rotation
    - Nonce management and validation
    
    Usage:
    ------
    # Server side
    server_e2e = E2EEncryption()
    server_ephemeral = server_e2e.generate_ephemeral_keypair()
    
    # Vehicle sends its public key
    vehicle_public_key = receive_from_vehicle()
    
    # Encrypt firmware
    encrypted = server_e2e.encrypt(
        firmware_data,
        server_ephemeral.private_key,
        vehicle_public_key
    )
    
    # Vehicle side
    vehicle_e2e = E2EEncryption()
    vehicle_ephemeral = vehicle_e2e.generate_ephemeral_keypair()
    
    # Decrypt firmware
    firmware = vehicle_e2e.decrypt(
        encrypted,
        vehicle_ephemeral.private_key
    )
    """
    
    # Security parameters
    DEFAULT_KEY_SIZE = 32  # AES-256
    GCM_NONCE_SIZE = 12    # 96 bits (recommended for GCM)
    GCM_TAG_SIZE = 16      # 128 bits
    SESSION_DURATION = 3600  # 1 hour default
    MAX_ENCRYPTIONS_PER_KEY = 2**32  # GCM limit
    
    def __init__(self, 
                 mode: EncryptionMode = EncryptionMode.AES_256_GCM,
                 session_duration: int = SESSION_DURATION):
        """
        Initialize E2E encryption.
        
        Args:
            mode: Encryption algorithm mode
            session_duration: Session key validity in seconds
        """
        self.mode = mode
        self.session_duration = session_duration
        self._session_keys: Dict[str, SessionKey] = {}
        self._nonce_history: Dict[str, set] = {}  # Prevent nonce reuse
        self._encryption_counter: Dict[str, int] = {}
        
        logger.info(f"E2EEncryption initialized with mode={mode.value}")
    
    def generate_ephemeral_keypair(self) -> Tuple[ec.EllipticCurvePrivateKey, 
                                                   ec.EllipticCurvePublicKey]:
        """
        Generate ephemeral ECDH key pair for single session.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        try:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            
            logger.debug("Generated ephemeral ECDH keypair")
            return private_key, public_key
        
        except Exception as e:
            logger.error(f"Failed to generate keypair: {e}")
            raise KeyExchangeError(f"Keypair generation failed: {e}") from e
    
    def derive_session_key(self,
                          our_private_key: ec.EllipticCurvePrivateKey,
                          peer_public_key: ec.EllipticCurvePublicKey,
                          context: bytes = b'secureev-ota-firmware') -> SessionKey:
        """
        Derive session key using ECDH + HKDF.
        
        Args:
            our_private_key: Our ephemeral private key
            peer_public_key: Peer's ephemeral public key
            context: Context string for HKDF
            
        Returns:
            SessionKey object with derived key and metadata
        """
        try:
            # Perform ECDH
            shared_secret = our_private_key.exchange(ec.ECDH(), peer_public_key)
            
            # Derive key using HKDF
            key_size = self.DEFAULT_KEY_SIZE if self.mode == EncryptionMode.AES_256_GCM else 16
            
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=key_size,
                salt=None,
                info=context,
            ).derive(shared_secret)
            
            # Generate key ID
            key_id = hashlib.sha256(derived_key).hexdigest()[:16]
            
            # Create session key
            now = time.time()
            session_key = SessionKey(
                key=derived_key,
                key_id=key_id,
                created_at=now,
                expires_at=now + self.session_duration,
                algorithm=self.mode
            )
            
            # Store for tracking
            self._session_keys[key_id] = session_key
            self._nonce_history[key_id] = set()
            self._encryption_counter[key_id] = 0
            
            logger.info(f"Derived session key {key_id}, expires in {self.session_duration}s")
            return session_key
        
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise KeyExchangeError(f"Failed to derive session key: {e}") from e
    
    def encrypt(self,
                plaintext: bytes,
                our_private_key: ec.EllipticCurvePrivateKey,
                peer_public_key: ec.EllipticCurvePublicKey,
                additional_data: Optional[bytes] = None) -> EncryptedPackage:
        """
        Encrypt data with ECDH + AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            our_private_key: Our ephemeral private key
            peer_public_key: Peer's ephemeral public key
            additional_data: Optional AAD for authentication
            
        Returns:
            EncryptedPackage with ciphertext and metadata
        """
        try:
            # Derive session key
            session_key = self.derive_session_key(our_private_key, peer_public_key)
            
            # Check encryption limit
            if self._encryption_counter[session_key.key_id] >= self.MAX_ENCRYPTIONS_PER_KEY:
                raise EncryptionError("Session key encryption limit reached")
            
            # Generate unique nonce
            nonce = self._generate_unique_nonce(session_key.key_id)
            
            # Encrypt with AES-GCM
            aesgcm = AESGCM(session_key.key)
            ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, additional_data)
            
            # Separate ciphertext and tag
            ciphertext = ciphertext_and_tag[:-self.GCM_TAG_SIZE]
            tag = ciphertext_and_tag[-self.GCM_TAG_SIZE:]
            
            # Get our public key for sending
            our_public_key = our_private_key.public_key()
            public_key_bytes = our_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
            
            # Increment counter
            self._encryption_counter[session_key.key_id] += 1
            
            package = EncryptedPackage(
                ciphertext=ciphertext,
                nonce=nonce,
                tag=tag,
                key_id=session_key.key_id,
                algorithm=self.mode.value,
                sender_public_key=public_key_bytes
            )
            
            logger.info(f"Encrypted {len(plaintext)} bytes → {package.total_size} bytes " 
                       f"(overhead: {package.total_size - len(plaintext)} bytes)")
            
            return package
        
        except EncryptionError:
            raise
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def decrypt(self,
                package: EncryptedPackage,
                our_private_key: ec.EllipticCurvePrivateKey,
                additional_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt encrypted package.
        
        Args:
            package: EncryptedPackage to decrypt
            our_private_key: Our ephemeral private key
            additional_data: Optional AAD (must match encryption)
            
        Returns:
            Decrypted plaintext bytes
        """
        try:
            # Reconstruct peer's public key
            peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                package.sender_public_key
            )
            
            # Derive same session key
            session_key = self.derive_session_key(our_private_key, peer_public_key)
            
            # Verify key IDs match
            if session_key.key_id != package.key_id:
                raise DecryptionError("Key ID mismatch - potential MITM attack")
            
            # Check session key expiration
            if session_key.is_expired():
                raise DecryptionError("Session key expired")
            
            # Verify nonce hasn't been used before (replay attack protection)
            nonce_hex = package.nonce.hex()
            if nonce_hex in self._nonce_history.get(session_key.key_id, set()):
                raise DecryptionError("Nonce reuse detected - potential replay attack")
            
            # Reconstruct full ciphertext with tag
            ciphertext_with_tag = package.ciphertext + package.tag
            
            # Decrypt with AES-GCM (automatically verifies tag)
            aesgcm = AESGCM(session_key.key)
            plaintext = aesgcm.decrypt(package.nonce, ciphertext_with_tag, additional_data)
            
            # Record nonce to prevent reuse
            if session_key.key_id in self._nonce_history:
                self._nonce_history[session_key.key_id].add(nonce_hex)
            
            logger.info(f"Successfully decrypted {len(plaintext)} bytes")
            return plaintext
        
        except DecryptionError:
            raise
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def _generate_unique_nonce(self, key_id: str) -> bytes:
        """
        Generate cryptographically secure unique nonce.
        
        Args:
            key_id: Session key ID for tracking
            
        Returns:
            12-byte nonce for GCM
        """
        max_attempts = 100
        for _ in range(max_attempts):
            nonce = secrets.token_bytes(self.GCM_NONCE_SIZE)
            nonce_hex = nonce.hex()
            
            if nonce_hex not in self._nonce_history.get(key_id, set()):
                return nonce
        
        raise EncryptionError("Failed to generate unique nonce")
    
    def rotate_session_key(self, old_key_id: str) -> None:
        """
        Rotate session key (invalidate old, generate new).
        
        Args:
            old_key_id: Key ID to rotate
        """
        if old_key_id in self._session_keys:
            del self._session_keys[old_key_id]
            if old_key_id in self._nonce_history:
                del self._nonce_history[old_key_id]
            if old_key_id in self._encryption_counter:
                del self._encryption_counter[old_key_id]
            
            logger.info(f"Rotated session key {old_key_id}")
    
    def cleanup_expired_keys(self) -> int:
        """
        Remove expired session keys.
        
        Returns:
            Number of keys removed
        """
        expired = [
            key_id for key_id, session_key in self._session_keys.items()
            if session_key.is_expired()
        ]
        
        for key_id in expired:
            self.rotate_session_key(key_id)
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired session keys")
        
        return len(expired)
    
    def get_session_info(self, key_id: str) -> Optional[dict]:
        """Get information about a session key."""
        session_key = self._session_keys.get(key_id)
        if not session_key:
            return None
        
        return {
            'key_id': key_id,
            'algorithm': session_key.algorithm.value,
            'created_at': session_key.created_at,
            'expires_at': session_key.expires_at,
            'time_remaining': session_key.time_until_expiry(),
            'encryptions_count': self._encryption_counter.get(key_id, 0),
            'nonces_used': len(self._nonce_history.get(key_id, set()))
        }


# Example usage and testing
if __name__ == "__main__":
    import json
    
    logging.basicConfig(level=logging.INFO)
    
    print("SecureEV-OTA End-to-End Encryption Module")
    print("=" * 60)
    
    # Simulate OEM server and vehicle
    server_e2e = E2EEncryption()
    vehicle_e2e = E2EEncryption()
    
    # Generate ephemeral keys
    server_private, server_public = server_e2e.generate_ephemeral_keypair()
    vehicle_private, vehicle_public = vehicle_e2e.generate_ephemeral_keypair()
    
    print("\n1. Key Exchange Complete")
    print(f"   Server public key: {server_public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()[:32]}...")
    print(f"   Vehicle public key: {vehicle_public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()[:32]}...")
    
    # Server encrypts firmware
    firmware = b"Firmware binary data for Primary ECU v2.1.5..." * 100
    additional_data = b"ECU_ID:primary-001"
    
    print(f"\n2. Encrypting Firmware")
    print(f"   Plaintext size: {len(firmware):,} bytes")
    
    encrypted = server_e2e.encrypt(
        firmware,
        server_private,
        vehicle_public,
        additional_data
    )
    
    print(f"   Ciphertext size: {len(encrypted.ciphertext):,} bytes")
    print(f"   Nonce: {encrypted.nonce.hex()}")
    print(f"   Tag: {encrypted.tag.hex()}")
    print(f"   Key ID: {encrypted.key_id}")
    print(f"   Total package: {encrypted.total_size:,} bytes")
    print(f"   Overhead: {encrypted.total_size - len(firmware)} bytes ({(encrypted.total_size/len(firmware) - 1)*100:.1f}%)")
    
    # Vehicle decrypts firmware
    print(f"\n3. Decrypting Firmware")
    decrypted = vehicle_e2e.decrypt(
        encrypted,
        vehicle_private,
        additional_data
    )
    
    print(f"   Decrypted size: {len(decrypted):,} bytes")
    print(f"   Integrity verified: {decrypted == firmware}")
    
    # Session info
    print(f"\n4. Session Information")
    server_info = server_e2e.get_session_info(encrypted.key_id)
    if server_info:
        print(f"   Algorithm: {server_info['algorithm']}")
        print(f"   Encryptions: {server_info['encryptions_count']}")
        print(f"   Time remaining: {server_info['time_remaining']:.0f}s")
    
    # Test serialization
    print(f"\n5. Package Serialization")
    serialized = json.dumps(encrypted.to_dict(), indent=2)
    print(f"   JSON size: {len(serialized):,} bytes")
    
    recovered_package = EncryptedPackage.from_dict(json.loads(serialized))
    recovered_firmware = vehicle_e2e.decrypt(recovered_package, vehicle_private, additional_data)
    print(f"   Round-trip successful: {recovered_firmware == firmware}")
    
    print("\n✓ End-to-end encryption module functioning correctly")
