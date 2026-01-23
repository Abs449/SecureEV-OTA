"""
SecureEV-OTA: Backend Service Tests

Integration tests for Phase 4 services:
- Director Service (Registration, DoS Protection)
- Image Repository (Metadata, Encryption)
"""

import pytest
from fastapi.testclient import TestClient
from src.services.director import app as director_app
from src.services.image_repo import app as image_repo_app
from src.crypto.ecc_core import ECCCore, ECCCurve

# Initialize Test Clients
director_client = TestClient(director_app)
image_repo_client = TestClient(image_repo_app)

ecc = ECCCore()

class TestDirectorService:
    """Tests for the Director API."""
    
    @pytest.fixture
    def vehicle_key(self):
        return ecc.generate_keypair()

    def test_vehicle_registration(self, vehicle_key):
        """Test successful vehicle registration."""
        payload = {
            "vehicle_id": "v-100",
            "public_key": vehicle_key.get_public_key_bytes().hex(),
            "hardware_id": "ecu-primary"
        }
        response = director_client.post("/register", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "registered"
        assert "key_id" in response.json()

    def test_duplicate_registration(self, vehicle_key):
        """Test that re-registering the same ID fails."""
        payload = {
            "vehicle_id": "v-101",
            "public_key": vehicle_key.get_public_key_bytes().hex(),
            "hardware_id": "ecu-primary"
        }
        # First registration
        director_client.post("/register", json=payload)
        # Second registration
        response = director_client.post("/register", json=payload)
        
        assert response.status_code == 409

    def test_check_updates_registered(self, vehicle_key):
        """Test update check for valid vehicle."""
        vid = "v-102"
        # Register first
        director_client.post("/register", json={
            "vehicle_id": vid,
            "public_key": vehicle_key.get_public_key_bytes().hex(),
            "hardware_id": "ecu-primary"
        })
        
        # Check updates
        response = director_client.post(f"/check_updates?vehicle_id={vid}")
        assert response.status_code == 200
        data = response.json()
        
        # Validate response structure (Uptane Targets)
        assert data["signed"]["_type"] == "targets"
        assert "firmware_v2.0.bin" in data["signed"]["targets"]

    def test_check_updates_unregistered(self):
        """Test update check for unknown vehicle."""
        response = director_client.post("/check_updates?vehicle_id=unknown_v")
        assert response.status_code == 404

    def test_dos_protection(self):
        """Test that rate limiting kicks in."""
        # Flood the API as a single "vehicle"
        # Note: In-memory simulation might be shared across tests, so use unique ID
        vid = "attacker-1"
        headers = {"X-Vehicle-ID": vid}
        
        # Send 15 requests (limit is 10)
        responses = []
        for _ in range(15):
            responses.append(director_client.get("/", headers=headers))
            
        # At least one should be 429
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes


class TestImageRepository:
    """Tests for the Image Repository API."""

    def test_get_metadata(self):
        """Test fetching standard metadata."""
        response = image_repo_client.get("/metadata/root")
        assert response.status_code == 200
        data = response.json()
        assert data["signed"]["_type"] == "root"

    def test_get_firmware_plain(self):
        """Test downloading unencrypted firmware."""
        response = image_repo_client.get("/targets/firmware_v2.0.bin")
        assert response.status_code == 200
        assert response.content == b"BINARY_FIRMWARE_CONTENT_V2.0"

    def test_get_firmware_encrypted(self):
        """Test downloading E2E encrypted firmware."""
        # Vehicle key for E2E
        kp = ecc.generate_keypair()
        pub_hex = kp.get_public_key_bytes().hex()
        
        response = image_repo_client.get(f"/targets/firmware_v2.0.bin?vehicle_pub_key={pub_hex}")
        assert response.status_code == 200
        
        data = response.json()
        assert "ciphertext" in data
        assert "nonce" in data
        assert "server_ephemeral_key" in data
