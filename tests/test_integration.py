"""
SecureEV-OTA: Backend Integration Tests

Tests the end-to-end flow between Director, Image Repo, and Vehicle Client.
"""

import pytest
import httpx
import asyncio
import os

# Test configuration
DIRECTOR_URL = "http://localhost:8000"
IMAGE_REPO_URL = "http://localhost:8001"


class TestDirectorService:
    """Tests for the Director Repository."""
    
    def test_health_check(self):
        """Director should return status online."""
        response = httpx.get(f"{DIRECTOR_URL}/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert "public_key" in data
    
    def test_register_vehicle(self):
        """Should register a new vehicle."""
        payload = {
            "vehicle_id": "TEST-VIN-001",
            "ecu_id": "PRIMARY-ECU-01",
            "public_key": "deadbeef" * 8,  # Placeholder
            "hardware_id": "EV-MODEL-S"
        }
        response = httpx.post(f"{DIRECTOR_URL}/register", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "success"
    
    def test_get_manifest(self):
        """Should return signed manifest for registered vehicle."""
        # First register
        payload = {
            "vehicle_id": "TEST-VIN-002",
            "ecu_id": "PRIMARY-ECU-02",
            "public_key": "cafebabe" * 8,
            "hardware_id": "EV-MODEL-S"
        }
        httpx.post(f"{DIRECTOR_URL}/register", json=payload)
        
        # Then get manifest
        response = httpx.get(f"{DIRECTOR_URL}/manifest/TEST-VIN-002")
        assert response.status_code == 200
        data = response.json()
        assert "signed" in data
        assert "signatures" in data


class TestImageRepoService:
    """Tests for the Image Repository."""
    
    def test_health_check(self):
        """Image Repo should return status online."""
        response = httpx.get(f"{IMAGE_REPO_URL}/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
    
    def test_upload_firmware(self):
        """Should upload firmware successfully."""
        firmware_data = b"MOCK_FIRMWARE_DATA_V1"
        response = httpx.post(
            f"{IMAGE_REPO_URL}/upload?filename=test-firmware.bin",
            content=firmware_data
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
    
    def test_get_targets_metadata(self):
        """Should return signed targets metadata."""
        response = httpx.get(f"{IMAGE_REPO_URL}/metadata/targets.json")
        assert response.status_code == 200
        data = response.json()
        assert "signed" in data
        assert "signatures" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
