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
import asyncio
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from src.crypto.ecc_core import ECCCore, ECCKeyPair, ECCCurve, public_key_from_bytes
from src.uptane.manager import MetadataManager, MetadataVerificationError
from src.security.encryption import E2EEncryption

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PrimaryECU")

# Connection timeout configuration (seconds)
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 30.0
DEFAULT_POOL_TIMEOUT = 10.0

# Retry configuration for transient failures
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5  # seconds
RETRY_STATUSES = {408, 429, 500, 502, 503, 504}


class UpdateError(Exception):
    """Raised when update process fails."""
    pass


class PrimaryECU:
    """
    Primary ECU client with robust connection handling and retry logic.
    """

    def __init__(self,
                 vehicle_id: str,
                 director_url: str,
                 image_repo_url: str,
                 director_public_key_hex: str,
                 connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
                 read_timeout: float = DEFAULT_READ_TIMEOUT,
                 pool_timeout: float = DEFAULT_POOL_TIMEOUT,
                 max_retries: int = MAX_RETRIES):

        self.vehicle_id = vehicle_id
        self.director_url = director_url.rstrip("/")
        self.image_repo_url = image_repo_url.rstrip("/")

        # Timeout configuration
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.pool_timeout = pool_timeout
        self.max_retries = max_retries

        # Crypto Engines
        self.ecc = ECCCore()
        self.e2e = E2EEncryption()
        self.metadata_manager = MetadataManager(self.ecc)

        # Identity
        self.keypair = self.ecc.generate_keypair()

        # Trust Anchors
        self._load_trust_anchors(director_public_key_hex)

        # Shared HTTP client for connection pooling
        self._http_client: Optional[httpx.AsyncClient] = None

    def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create a shared HTTP client with proper timeouts."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=self.connect_timeout,
                    read=self.read_timeout,
                    write=self.connect_timeout,
                    pool=self.pool_timeout
                ),
                limits=httpx.Limits(
                    max_connections=10,
                    max_keepalive_connections=5
                ),
                follow_redirects=True
            )
        return self._http_client

    async def close(self):
        """Close the HTTP client."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _request_with_retry(self,
                                   method: str,
                                   url: str,
                                   **kwargs) -> httpx.Response:
        """
        Make HTTP request with retry logic for transient failures.

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional arguments for httpx request

        Returns:
            Response object

        Raises:
            UpdateError: If all retries fail
        """
        client = self._get_http_client()
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                response = await client.request(method, url, **kwargs)

                # Retry on specific status codes
                if response.status_code in RETRY_STATUSES:
                    if attempt < self.max_retries - 1:
                        wait_time = RETRY_BACKOFF_BASE * (2 ** attempt)
                        logger.warning(f"Retry {attempt + 1}/{self.max_retries} for {url} "
                                       f"after {response.status_code}, waiting {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue
                    # Final attempt exhausted - raise UpdateError with status details
                    raise UpdateError(f"Request failed after {self.max_retries} attempts: "
                                      f"HTTP {response.status_code} - {response.text[:200]}")

            except (httpx.ConnectError, httpx.ConnectTimeout,
                    httpx.ReadTimeout, httpx.PoolTimeout) as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    wait_time = RETRY_BACKOFF_BASE * (2 ** attempt)
                    logger.warning(f"Connection attempt {attempt + 1}/{self.max_retries} failed "
                                   f"for {url}: {e}, retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"All connection attempts failed for {url}: {e}")

        raise UpdateError(f"Request failed after {self.max_retries} attempts: {last_exception}")

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
            "ecu_id": f"PRIMARY-ECU-{self.vehicle_id[-6:]}",
            "public_key": self.keypair.get_public_key_bytes().hex(),
            "hardware_id": "EV-MODEL-S"
        }

        try:
            resp = await self._request_with_retry(
                "POST",
                f"{self.director_url}/register",
                json=payload
            )
            resp.raise_for_status()
            logger.info(f"Registered vehicle {self.vehicle_id}")
        except httpx.HTTPStatusError as e:
            # 409 means already registered, which is fine
            status = e.response.status_code if getattr(e, "response", None) is not None else None
            if status == 409:
                logger.info("Vehicle already registered")
            else:
                raise UpdateError(f"Registration failed: {e}")
        except UpdateError:
            raise
        except Exception as e:
            raise UpdateError(f"Registration request failed: {e}")

    async def poll_for_updates(self):
        """
        Main update cycle:
        1. Check Director for assigned targets
        2. If new target, fetch signed metadata chain
        3. Verify metadata
        4. Download and Decrypt image
        """
        logger.info("Polling for updates...")

        # 1. Ask Director
        try:
            resp = await self._request_with_retry(
                "POST",
                f"{self.director_url}/check_updates",
                params={"vehicle_id": self.vehicle_id},
                headers={"X-Vehicle-ID": self.vehicle_id}
            )
            resp.raise_for_status()
            targets_json = resp.text
        except httpx.HTTPStatusError as e:
            # Server responded with a non-2xx status
            resp = getattr(e, "response", None)
            status = resp.status_code if resp is not None else None
            # If rate-limited, surface retry-after to caller via UpdateError
            if status == 429:
                retry_after = None
                try:
                    retry_header = resp.headers.get("Retry-After") if resp is not None else None
                    if retry_header is not None:
                        retry_after = float(retry_header)
                except Exception:
                    retry_after = None

                ex = UpdateError("Rate limit exceeded")
                if retry_after is not None:
                    setattr(ex, "retry_after", retry_after)
                raise ex

            logger.error(f"Failed to check updates: {e}")
            return
        except UpdateError:
            raise
        except Exception as e:
            logger.error(f"Failed to check updates (network): {e}")
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

        await self._download_and_install(filename, target_info)

    async def _download_and_install(self, filename: str, target_info: Dict):
        """Securely download and install firmware."""

        # 1. Request Download (with our public key for E2E encryption and vehicle_id for rate limiting)
        download_url = f"{self.image_repo_url}/targets/{filename}"
        params = {
            "vehicle_pub_key": self.keypair.get_public_key_bytes().hex(),
            "vehicle_id": self.vehicle_id
        }

        try:
            logger.info(f"Downloading {filename}...")
            resp = await self._request_with_retry(
                "GET",
                download_url,
                params=params
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            logger.error(f"Download failed: {e}")
            raise UpdateError(f"Download failed: {e}")
        
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
