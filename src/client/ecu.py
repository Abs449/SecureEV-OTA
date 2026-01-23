"""
SecureEV-OTA: Vehicle Consumer (Primary ECU)

This module implements the Primary ECU login that runs on the vehicle.
It interacts with:
1. Director Service: To get assigned updates
2. Image Repository: To get metadata and encrypted firmware

It performs all Uptane verification and E2E decryption.
"""

import httpx
import json
import logging
from typing import Dict, Any, Optional

from src.crypto.ecc_core import ECCCore, ECCKeyPair, ECCCurve, public_key_from_bytes
from src.uptane.manager import MetadataManager, MetadataVerificationError
from src.security.encryption import E2EEncryption

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PrimaryECU")

class UpdateError(Exception):
    """Raised when update process fails."""
    pass

class PrimaryECU:
    def __init__(self, 
                 vehicle_id: str, 
                 director_url: str, 
                 unknown_image_repo_url: str,
                 director_public_key_hex: str):
        
        self.vehicle_id = vehicle_id
        self.director_url = director_url.rstrip("/")
        self.image_repo_url = unknown_image_repo_url.rstrip("/")
        
        # Crypto Engines
        self.ecc = ECCCore()
        self.e2e = E2EEncryption()
        self.metadata_manager = MetadataManager(self.ecc)
        
        # Identity
        self.keypair = self.ecc.generate_keypair()
        
        # Trust Anchors
        # In real life, these are burned into ROM or verified secure storage
        self._load_trust_anchors(director_public_key_hex)
        
    def _load_trust_anchors(self, director_key_hex: str):
        """Bootstrap trust."""
        # Trust the Director's key
        pub_bytes = bytes.fromhex(director_key_hex)
        pub_key = public_key_from_bytes(pub_bytes)
        # Director usually signs Root or Targets. For simplicity in this demo,
        # we treat it as a trusted signer for MetadataManager
        # In full Uptane, we'd have a Root file first.
        # Here we manually inject it to the trusted_keys of the manager.
        # But wait, MetadataManager uses key_ids. 
        # We'll assume the director key ID is computable.
        key_id = self.ecc._generate_key_id(pub_key)
        self.metadata_manager.trusted_keys[key_id] = pub_key
        
    async def register(self):
        """Register with the Director."""
        payload = {
            "vehicle_id": self.vehicle_id,
            "public_key": self.keypair.get_public_key_bytes().hex(),
            "hardware_id": "ecu-primary"
        }
        
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(f"{self.director_url}/register", json=payload)
                resp.raise_for_status()
                logger.info(f"Registered vehicle {self.vehicle_id}")
            except httpx.HTTPError as e:
                # 409 means already registered, which is fine
                if resp.status_code == 409:
                    logger.info("Vehicle already registered")
                else:
                    raise UpdateError(f"Registration failed: {e}")

    async def poll_for_updates(self):
        """
        Main update cycle:
        1. Check Director for assigned targets
        2. If new target, fetch signed metadata chain
        3. Verify metadata
        4. Download and Decrypt image
        """
        logger.info("Polling for updates...")
        
        async with httpx.AsyncClient() as client:
            # 1. Ask Director
            try:
                resp = await client.post(
                    f"{self.director_url}/check_updates", 
                    params={"vehicle_id": self.vehicle_id},
                    # Add headers for DoS protection auth if needed
                    headers={"X-Vehicle-ID": self.vehicle_id}
                )
                resp.raise_for_status()
                targets_json = resp.text
            except httpx.HTTPError as e:
                logger.error(f"Failed to check updates: {e}")
                return

            # 2. Verify Director's Response (The personalized Targets file)
            try:
                targets_meta = self.metadata_manager.verify_metadata(targets_json, "targets")
                logger.info("Director response verified")
            except MetadataVerificationError as e:
                logger.error(f"Security Warning: Director returned invalid metadata: {e}")
                return
            
            # 3. Check if there are targets
            if not targets_meta.targets:
                logger.info("No updates assigned.")
                return
            
            # 4. Process Target (Assume single target for simplicity)
            filename, target_info = list(targets_meta.targets.items())[0]
            logger.info(f"Found update: {filename}")
            
            await self._download_and_install(client, filename, target_info)

    async def _download_and_install(self, client: httpx.AsyncClient, filename: str, target_info: Dict):
        """Securely download and install firmware."""
        
        # 1. Request Download (with our public key for E2E encryption)
        download_url = f"{self.image_repo_url}/targets/{filename}"
        params = {"vehicle_pub_key": self.keypair.get_public_key_bytes().hex()}
        
        logger.info(f"Downloading {filename}...")
        resp = await client.get(download_url, params=params)
        resp.raise_for_status()
        
        # 2. Handle Encryption
        try:
            package = resp.json()
            # If server returned encryption envelope
            if "ciphertext" in package:
                logger.info("Received encrypted payload. Decrypting...")
                decrypted_bytes = self._decrypt_package(package)
            else:
                logger.warning("Received plain payload (Not E2E encrypted).")
                decrypted_bytes = resp.content
                
            # 3. Verify Integrity (Hash Check)
            # In real Uptane, we check hashes against the verified Targets metadata
            expected_hash = target_info["hashes"]["sha256"]
            actual_hash = self._compute_hash(decrypted_bytes)
            
            if actual_hash != expected_hash:
                raise UpdateError("Hash mismatch! Firmware corrupted or tampered.")
                
            logger.info("Integrity check passed.")
            
            # 4. Install (Simulated)
            self._install_firmware(decrypted_bytes)
            
        except Exception as e:
            logger.error(f"Update failed: {e}")
            raise

    def _decrypt_package(self, package: Dict[str, Any]) -> bytes:
        """Decrypt E2E package using our private key."""
        try:
            server_pub_hex = package["server_ephemeral_key"]
            ciphertext_hex = package["ciphertext"]
            nonce_hex = package["nonce"]
            
            # Reconstruct objects
            server_pub = public_key_from_bytes(
                bytes.fromhex(server_pub_hex), 
                ECCCurve.SECP256R1
            )
            
            # Derive session key
            session_key = self.e2e.establish_session_key(
                self.keypair.private_key, 
                server_pub
            )
            
            # Decrypt
            plaintext = self.e2e.decrypt_payload(
                bytes.fromhex(ciphertext_hex),
                bytes.fromhex(nonce_hex),
                session_key,
                # Authenticated metadata (filename) if any was sent
                json.dumps(package.get("metadata", {})).encode() if "metadata" in package else None
            )
            
            return plaintext
        except Exception as e:
            raise UpdateError(f"Decryption error: {type(e).__name__} {e}")

    def _compute_hash(self, data: bytes) -> str:
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def _install_firmware(self, data: bytes):
        """Simulate installation."""
        logger.info(f"Writing {len(data)} bytes to flash memory...")
        # In simulation, we might write to a file
        logging.info("SUCCESS: Firmware installed and verified secure.")
