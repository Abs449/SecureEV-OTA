"""
SecureEV-OTA: Image Repository

This service stores the actual firmware binary images and the signed
metadata that describes them.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Query
from fastapi.responses import FileResponse
import os
import hashlib
import logging
import json

from src.crypto.ecc_core import ECCCore, ECCKeyPair, ECCCurve, public_key_from_bytes
from src.uptane.metadata import TargetsMetadata
from src.security.encryption import E2EEncryption

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ImageRepo")

app = FastAPI(title="SecureEV-OTA Image Repository")

# Core components
ecc = ECCCore(ECCCurve.SECP256R1)
IMAGE_REPO_KEY = ecc.generate_keypair()

# Path configuration
STORAGE_PATH = "repo_storage"
IMAGES_PATH = os.path.join(STORAGE_PATH, "images")
METADATA_PATH = os.path.join(STORAGE_PATH, "metadata")

# Create storage directories
os.makedirs(IMAGES_PATH, exist_ok=True)
os.makedirs(METADATA_PATH, exist_ok=True)

@app.get("/")
async def root():
    return {
        "service": "SecureEV-OTA Image Repository",
        "status": "online",
        "public_key": IMAGE_REPO_KEY.get_public_key_bytes().hex()
    }

@app.get("/metadata/targets.json")
async def get_targets_metadata():
    """Return the generic targets metadata signed by the Image Repo."""
    # In a production system, this would be a static file signed offline
    # For the simulator, we generate it dynamically for existing images
    
    manifest = TargetsMetadata(
        expires="2026-12-31T23:59:59Z",
        version=1
    )
    
    # List all files in images directory
    for filename in os.listdir(IMAGES_PATH):
        filepath = os.path.join(IMAGES_PATH, filename)
        if os.path.isfile(filepath):
            with open(filepath, "rb") as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
                file_len = len(content)
                
            # Hardware ID detection from filename or database
            # For demo, everything is generic EV-MODEL-S
            manifest.add_target(filename, file_hash, file_len, "EV-MODEL-S")
    
    manifest.sign(IMAGE_REPO_KEY, ecc)
    return manifest.to_dict()

@app.get("/images/{filename}")
async def download_image(filename: str):
    """Serve the actual firmware binary."""
    filepath = os.path.join(IMAGES_PATH, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Image not found")
    
    return FileResponse(filepath)

@app.post("/upload")
async def upload_image(filename: str, request: Request):
    """
    Diagnostic/Admin endpoint to upload firmware.
    """
    payload = await request.body()
    filepath = os.path.join(IMAGES_PATH, filename)
    with open(filepath, "wb") as f:
        f.write(payload)
    
    logger.info(f"Uploaded new firmware image: {filename}")
    return {"status": "success", "filename": filename}

# Initialize E2E encryption
e2e = E2EEncryption()

@app.get("/targets/{filename}")
async def get_encrypted_target(filename: str, vehicle_pub_key: str = Query(...)):
    """
    Serve firmware encrypted for the requesting vehicle.
    
    The vehicle sends its public key, we generate an ephemeral keypair,
    derive a shared secret, and encrypt the firmware for only that vehicle.
    """
    filepath = os.path.join(IMAGES_PATH, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Image not found")
    
    # Read firmware
    with open(filepath, "rb") as f:
        firmware_data = f.read()
    
    # Parse vehicle's public key
    try:
        vehicle_pub = public_key_from_bytes(bytes.fromhex(vehicle_pub_key))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {e}")
    
    # Generate ephemeral keypair for forward secrecy
    ephemeral_keypair = ecc.generate_keypair()
    
    # Derive session key
    session_key = e2e.establish_session_key(
        ephemeral_keypair.private_key,
        vehicle_pub
    )
    
    # Encrypt firmware
    metadata = {"filename": filename, "size": len(firmware_data)}
    nonce, ciphertext = e2e.encrypt_payload(
        firmware_data, 
        session_key, 
        json.dumps(metadata).encode()
    )
    
    logger.info(f"Encrypted {filename} for vehicle")
    
    return {
        "server_ephemeral_key": ephemeral_keypair.get_public_key_bytes().hex(),
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "metadata": metadata
    }

if __name__ == "__main__":
    import uvicorn
    # Image repo usually runs on 8001
    uvicorn.run(app, host="0.0.0.0", port=8001)
