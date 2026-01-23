"""
SecureEV-OTA: Client Integration Tests

Tests the PrimaryECU update logic by mocking the backend services.
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from src.client.ecu import PrimaryECU, UpdateError

# Mock Data
MOCK_DIRECTOR_URL = "http://director"
MOCK_REPO_URL = "http://repo"
MOCK_DIRECTOR_KEY_HEX = "04" + "00"*64  # invalid key but correct length for parsing

@pytest.fixture
def ecu():
    """Create an ECU instance with mocked trust anchors."""
    # We need a real public key to pass validation
    from src.crypto.ecc_core import ECCCore
    ecc = ECCCore()
    kp = ecc.generate_keypair()
    pub_hex = kp.get_public_key_bytes().hex()
    
    return PrimaryECU(
        vehicle_id="v-test", 
        director_url=MOCK_DIRECTOR_URL,
        unknown_image_repo_url=MOCK_REPO_URL,
        director_public_key_hex=pub_hex
    )

@pytest.mark.asyncio
async def test_successful_update_flow(ecu):
    """Test a full update cycle with mocked networking."""
    
    # 1. Mock Director Response (Targets Metadata)
    # We need valid signed metadata for the client to verify
    from src.uptane.metadata import TargetsMetadata
    targets = TargetsMetadata(expires="2030-01-01", version=1)
    targets.add_target(
        filename="firmware.bin",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # hash of empty bytes
        length=0,
        hardware_id="ecu-primary"
    )
    # ECU needs to trust the signer. ECU trusts `ecu.metadata_manager.trusted_keys`.
    # Let's sign with a trusted key we inject.
    signer_kp = ecu.ecc.generate_keypair()
    ecu.metadata_manager.trusted_keys[signer_kp.key_id] = signer_kp.public_key
    targets.sign(signer_kp, ecu.ecc)
    
    # 2. Mock Repo Response (Encrypted Payload)
    # We need to craft a valid E2E package
    from src.security.encryption import E2EEncryption
    e2e = E2EEncryption()
    server_kp = e2e.ecdh.generate_ephemeral_keypair()
    session_key = e2e.establish_session_key(server_kp.private_key, ecu.keypair.public_key)
    
    firmware_content = b"" # matches the hash above
    package_bytes = e2e.package_encrypted_update(
        data=firmware_content,
        session_key=session_key,
        metadata={"filename": "firmware.bin"}
    )
    package_json = json.loads(package_bytes)
    package_json["server_ephemeral_key"] = server_kp.get_public_key_bytes().hex()
    
    # 3. Setup Mocks
    mock_post = MagicMock()
    mock_post.return_value.status_code = 200
    mock_post.return_value.text = json.dumps(targets.to_dict())
    mock_post.return_value.raise_for_status = MagicMock()
    
    mock_get = MagicMock()
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = package_json
    mock_get.return_value.raise_for_status = MagicMock()

    # Patches
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as patched_post:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as patched_get:
            patched_post.return_value = mock_post.return_value
            patched_get.return_value = mock_get.return_value
            
            # RUN
            await ecu.poll_for_updates()
            
            # VERIFY
            # Polled director?
            patched_post.assert_called_with(
                f"{MOCK_DIRECTOR_URL}/check_updates", 
                params={"vehicle_id": "v-test"},
                headers={"X-Vehicle-ID": "v-test"}
            )
            # Downloaded from repo?
            args, kwargs = patched_get.call_args
            assert args[0] == f"{MOCK_REPO_URL}/targets/firmware.bin"
            
            # Installation logged?
            # (We could mock logger, but execution without exception is success)

@pytest.mark.asyncio
async def test_update_tampered_payload_hash_mismatch(ecu):
    """Test that a tampered payload (valid E2E but wrong hash) is rejected."""
    
    # ... Setup metadata ...
    from src.uptane.metadata import TargetsMetadata
    targets = TargetsMetadata(expires="2030-01-01", version=1)
    targets.add_target(
        filename="firmware.bin",
        file_hash="1111111111111111111111111111111111111111111111111111111111111111", # WRONG hash
        length=0,
        hardware_id="ecu-primary"
    )
    signer_kp = ecu.ecc.generate_keypair()
    ecu.metadata_manager.trusted_keys[signer_kp.key_id] = signer_kp.public_key
    targets.sign(signer_kp, ecu.ecc)
    
    # ... Setup payload ...
    from src.security.encryption import E2EEncryption
    e2e = E2EEncryption()
    server_kp = e2e.ecdh.generate_ephemeral_keypair()
    session_key = e2e.establish_session_key(server_kp.private_key, ecu.keypair.public_key)
    package_bytes = e2e.package_encrypted_update(b"", session_key, {"filename": "firmware.bin"}) # Payload is empty bytes
    package_json = json.loads(package_bytes)
    package_json["server_ephemeral_key"] = server_kp.get_public_key_bytes().hex()
    
    # ... Mocks ...
    mock_post = MagicMock()
    mock_post.return_value.text = json.dumps(targets.to_dict())
    mock_post.return_value.status_code = 200
    mock_get = MagicMock()
    mock_get.return_value.json.return_value = package_json
    mock_get.return_value.status_code = 200

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as p_post, \
         patch("httpx.AsyncClient.get", new_callable=AsyncMock) as p_get:
            p_post.return_value = mock_post.return_value
            p_get.return_value = mock_get.return_value
            
            # Expect failure
            with pytest.raises(UpdateError) as excinfo:
                await ecu.poll_for_updates()
            assert "Hash mismatch" in str(excinfo.value)
