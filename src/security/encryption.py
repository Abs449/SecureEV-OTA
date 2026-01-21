"""
SecureEV-OTA: End-to-End Encryption

This module provides mandatory end-to-end encryption for firmware payloads,
addressing the confidentiality gap in the original Uptane framework.
It uses ECDH for key exchange and AES-256-GCM for authenticated encryption.
"""

from __future__ import annotations

from typing import Tuple, Dict, Any
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec

from src.crypto.ecc_core import ECDHKeyExchange, ECCCurve


class E2EEncryption:
    """
    Handles end-to-end encryption of firmware updates.
    
    Improvements over Uptane:
    - Mandatory encryption (vs optional/transport-only)
    - Forward secrecy via ephemeral session keys
    - Authenticated encryption with AES-GCM
    """
    
    def __init__(self, curve: ECCCurve = ECCCurve.SECP256R1):
        """
        Initialize the E2E encryption module.
        
        Args:
            curve: Elliptic curve to use for ECDH
        """
        self.ecdh = ECDHKeyExchange(curve)
        
    def establish_session_key(self, 
                               private_key: ec.EllipticCurvePrivateKey, 
                               peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Establish a shared session key using ECDH.
        
        Args:
            private_key: Our private key (usually ephemeral)
            peer_public_key: Peer's public key (usually ephemeral)
            
        Returns:
            Derived session key (32 bytes for AES-256)
        """
        return self.ecdh.derive_session_key(private_key, peer_public_key)

    def encrypt_payload(self, 
                        data: bytes, 
                        session_key: bytes, 
                        associated_data: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Data to encrypt
            session_key: 32-byte session key
            associated_data: Optional non-encrypted data to authenticate
            
        Returns:
            Tuple of (nonce, ciphertext)
        """
        aesgcm = AESGCM(session_key)
        nonce = self.ecdh.generate_nonce()
        ciphertext = aesgcm.encrypt(nonce, data, associated_data)
        return nonce, ciphertext

    def decrypt_payload(self, 
                        ciphertext: bytes, 
                        nonce: bytes, 
                        session_key: bytes, 
                        associated_data: bytes = None) -> bytes:
        """
        Decrypt and verify data using AES-256-GCM.
        
        Args:
            ciphertext: Ciphertext containing the tag
            nonce: 12-byte nonce
            session_key: 32-byte session key
            associated_data: Associated data used for authentication
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            cryptography.exceptions.InvalidTag: If verification fails
        """
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    def package_encrypted_update(self, 
                                 data: bytes, 
                                 session_key: bytes, 
                                 metadata: Dict[str, Any] = None) -> bytes:
        """
        Encrypt and package update with metadata for transport.
        
        Args:
            data: Firmware data
            session_key: Derived session key
            metadata: Optional metadata to include (will be authenticated)
            
        Returns:
            JSON-serialized package bytes
        """
        assoc_data = json.dumps(metadata).encode() if metadata else None
        nonce, ciphertext = self.encrypt_payload(data, session_key, assoc_data)
        
        package = {
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "metadata": metadata
        }
        
        return json.dumps(package).encode()

    def unpack_encrypted_update(self, 
                                package_bytes: bytes, 
                                session_key: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """
        Unpack and decrypt update package.
        
        Args:
            package_bytes: JSON-serialized package
            session_key: Derived session key
            
        Returns:
            Tuple of (decrypted_data, metadata)
        """
        package = json.loads(package_bytes.decode())
        ciphertext = bytes.fromhex(package["ciphertext"])
        nonce = bytes.fromhex(package["nonce"])
        metadata = package.get("metadata")
        
        assoc_data = json.dumps(metadata).encode() if metadata else None
        plaintext = self.decrypt_payload(ciphertext, nonce, session_key, assoc_data)
        
        return plaintext, metadata
