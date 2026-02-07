"""
SecureEV-OTA: Director Repository

This service acts as the "brain" of the OTA system, managing vehicle inventories
and generating custom, signed manifests for each vehicle.
"""

from fastapi import FastAPI, HTTPException, Request, Depends, Query
from pydantic import BaseModel
from typing import Dict, List, Optional
import time
import json
import logging

from src.crypto.ecc_core import ECCCore, ECCKeyPair, ECCCurve
from src.uptane.metadata import TargetsMetadata
from src.security.dos_protection import DoSProtection

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Director")

app = FastAPI(title="SecureEV-OTA Director")

# Core components
ecc = ECCCore(ECCCurve.SECP256R1)
dos = DoSProtection()

# Director's signing key (in a real app, this would be loaded from a secure KMS)
# For the demo, we generate it on startup
DIRECTOR_KEY = ecc.generate_keypair()

# Mock database
class MockDB:
    def __init__(self):
        self.vehicles = {}
        self.firmware_inventory = {
            "EV-MODEL-S": {
                "version": "v2.1.0",
                "filename": "firmware-v210.bin",
                "hash": "3064cdb38ee2f0b0c9dee09dc81fe413954ac3c7b1e936a693aae11ad83ed60d",
                "size": 1029
            }
        }

db = MockDB()

class VehicleReg(BaseModel):
    vehicle_id: str
    ecu_id: str
    public_key: str
    hardware_id: str

@app.get("/")
async def root():
    return {
        "service": "SecureEV-OTA Director",
        "status": "online",
        "public_key": DIRECTOR_KEY.get_public_key_bytes().hex()
    }

@app.post("/register")
async def register(reg: VehicleReg):
    """Register a new vehicle/ECU with the director."""
    db.vehicles[reg.vehicle_id] = {
        "ecu_id": reg.ecu_id,
        "public_key": reg.public_key,
        "hardware_id": reg.hardware_id,
        "last_seen": time.time()
    }
    logger.info(f"Registered vehicle {reg.vehicle_id}")
    return {"status": "success", "message": f"Vehicle {reg.vehicle_id} registered"}

@app.get("/manifest/{vehicle_id}")
async def get_manifest(vehicle_id: str):
    """
    Generate a signed manifest for a specific vehicle.
    This manifest tells the vehicle EXACTLY which firmware version it should have.
    """
    # 1. Check DoS Protection
    if not dos.is_request_allowed(vehicle_id):
        logger.warning(f"DoS protection triggered for {vehicle_id}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # 2. Lookup vehicle
    if vehicle_id not in db.vehicles:
        dos.report_invalid_request(vehicle_id)
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    v_data = db.vehicles[vehicle_id]
    hw_id = v_data["hardware_id"]
    
    # 3. Find applicable update
    if hw_id not in db.firmware_inventory:
        return {"status": "up_to_date", "message": "No new updates for this hardware version"}
    
    fw = db.firmware_inventory[hw_id]
    
    # 4. Generate signed Uptane Targets Metadata
    # In a real environment, we'd check if the vehicle already has this version
    manifest = TargetsMetadata(
        expires="2026-12-31T23:59:59Z",
        version=1
    )
    
    # Add the specific target for this ECU
    manifest.add_target(
        filename=fw["filename"],
        file_hash=fw["hash"],
        length=fw["size"],
        hardware_id=hw_id
    )
    
    # Sign it with Director's key
    manifest.sign(DIRECTOR_KEY, ecc)
    
    logger.info(f"Generated manifest for {vehicle_id} (Version: {fw['version']})")
    
    return manifest.to_dict()

@app.post("/check_updates")
async def check_updates(vehicle_id: str = Query(...)):
    """
    Alternative endpoint matching client expectation.
    Returns signed targets metadata for a specific vehicle.
    """
    # Reuse get_manifest logic
    return await get_manifest(vehicle_id)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
