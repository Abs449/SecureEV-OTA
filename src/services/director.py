"""
SecureEV-OTA: Director Service

The Director service ("The Brain") is responsible for assigning updates to vehicles.
It generates custom Roles and Targets metadata for each vehicle, ensuring that
vehicles only install updates intended for them.

Integrates:
- DoS Protection (Phase 2)
- Metadata Signing (Phase 3)
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Dict, Any, List
import time

from src.security.dos_protection import DoSProtection
from src.uptane.metadata import TargetsMetadata, RootMetadata
from src.crypto.ecc_core import ECCCore, ECCCurve

app = FastAPI(title="SecureEV-OTA Director")

# Initialize Security Modules
dos_protection = DoSProtection(
    global_capacity=1000, 
    global_rate=100,
    per_vehicle_capacity=10, 
    per_vehicle_rate=1
)

ecc = ECCCore()
director_key = ecc.generate_keypair()  # In prod, load from secure storage

# In-memory "Database"
registered_vehicles: Dict[str, str] = {}  # vehicle_id -> public_key_hex


class VehicleRegistration(BaseModel):
    vehicle_id: str
    public_key: str
    hardware_id: str


@app.middleware("http")
async def check_rate_limit(request: Request, call_next):
    """
    Middleware to enforce DoS protection.
    Checks IP-based limits for anonymous endpoints or extraction of IDs for auth ones.
    """
    # Simple simulation: Extract vehicle_id from header if present
    vehicle_id = request.headers.get("X-Vehicle-ID", "anonymous")
    
    if not dos_protection.is_request_allowed(vehicle_id):
        return build_dos_response()
        
    response = await call_next(request)
    return response


def build_dos_response():
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please back off."}
    )


@app.get("/public_key")
async def get_public_key():
    """
    [DEMO ONLY] Expose public key so clients can bootstrap trust.
    In production, this would be baked into the firmware.
    """
    return {"public_key": director_key.get_public_key_bytes().hex()}


@app.post("/register")
async def register_vehicle(registration: VehicleRegistration):
    """
    Register a new vehicle ECU.
    """
    if registration.vehicle_id in registered_vehicles:
        raise HTTPException(status_code=409, detail="Vehicle already registered")
        
    registered_vehicles[registration.vehicle_id] = registration.public_key
    return {"status": "registered", "key_id": director_key.key_id}


@app.post("/check_updates")
async def check_updates(vehicle_id: str):
    """
    Generate a personalized Targets metadata file for the vehicle.
    """
    if vehicle_id not in registered_vehicles:
        # In Uptane, we might still return a response to avoid enumeration,
        # but for this demo, we'll be explicit
        raise HTTPException(status_code=404, detail="Vehicle not found")

    # Create dynamic Targets metadata
    # In a real system, this logic would check the inventory DB
    targets = TargetsMetadata(
        expires="2027-01-01T00:00:00",
        version=1
    )
    
    # Assign a dummy update
    targets.add_target(
        filename="firmware_v2.0.bin",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        length=1024,
        hardware_id="ecu-primary"
    )
    
    # Sign it with Director's key
    targets.sign(director_key, ecc)
    
    return targets.to_dict()


@app.get("/")
async def root():
    return {"service": "SecureEV-OTA Director", "status": "online"}

@app.get("/key")
async def get_public_key():
    """
    Debug endpoint to get the ephemeral Director public key.
    In production, this key would be pre-shared or Certificate Authority signed.
    """
    return {"public_key": director_key.get_public_key_bytes().hex()}
