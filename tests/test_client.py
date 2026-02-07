"""
SecureEV-OTA: Live Client Integration Tests

Tests the PrimaryECU update logic against real running backend services.
Requires Director (8000) and Image Repo (8001) to be running.
"""

import pytest
import pytest_asyncio
import httpx
import logging
from src.client.ecu import PrimaryECU, UpdateError
from src.crypto.ecc_core import ECCCore

# Real Service URLs
DIRECTOR_URL = "http://localhost:8000"
REPO_URL = "http://localhost:8001"

@pytest_asyncio.fixture
async def director_public_key():
    """Fetch the real Director public key."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(DIRECTOR_URL)
            resp.raise_for_status()
            data = resp.json()
            return data["public_key"]
        except httpx.HTTPError as e:
            pytest.fail(f"Could not connect to Director at {DIRECTOR_URL}: {e}")

@pytest_asyncio.fixture
async def ecu(director_public_key):
    """Create an ECU instance connected to real services."""
    vehicle_id = "v-test-integration"
    
    ecu = PrimaryECU(
        vehicle_id=vehicle_id, 
        director_url=DIRECTOR_URL,
        image_repo_url=REPO_URL,
        director_public_key_hex=director_public_key
    )
    return ecu

@pytest.mark.asyncio
async def test_live_successful_update_flow(ecu):
    """Test a full update cycle against the real backend."""
    
    # 1. Register
    await ecu.register()
    
    # 2. Poll & Update
    # This relies on the Director serving 'firmware-v210.bin' for any registered vehicle
    # And Image Repo having 'firmware-v210.bin' uploaded (which simulation.py does on start)
    await ecu.poll_for_updates()
    
    # If no exception raised, success.
    # We can inspect internal state if needed, or rely on logs.

@pytest.mark.asyncio
async def test_live_tampered_payload_hash_mismatch(ecu):
    """
    Test hash mismatch by tricking the client into downloading a modified file.
    
    Strategy:
    1. Upload a valid file to verify baseline.
    2. Upload a malicious file with SAME filename to the repo storage directly (bypassing director?).
       - Director still thinks hash is VALID_HASH.
       - Repo serves MALICIOUS_FILE.
       - Client downloads MALICIOUS_FILE, computes hash, mismatch!
    """
    import os
    
    # 1. Ensure a clean state is working first (optional, skipped to save time)
    await ecu.register()
    
    # 2. Tamper with the file in the repo storage
    # We know the repo storage path is ./repo_storage/images
    repo_path = "repo_storage/images/firmware-v210.bin"
    if not os.path.exists(repo_path):
        pytest.skip(f"Repo storage not found at {repo_path}, cannot tamper for test.")
        
    # Read original content
    with open(repo_path, "rb") as f:
        original_content = f.read()
        
    try:
        # Overwrite with garbage
        with open(repo_path, "wb") as f:
            f.write(b"MALICIOUS_BYTECODE_INJECTED")
            
        # 3. Run Update - Expect Failure
        with pytest.raises(UpdateError) as excinfo:
            await ecu.poll_for_updates()
        
        assert "Hash mismatch" in str(excinfo.value)
        
    finally:
        # Restore original file to not break other tests/simulation
        with open(repo_path, "wb") as f:
            f.write(original_content)
