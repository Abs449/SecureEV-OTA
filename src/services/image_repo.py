"""
SecureEV-OTA: Image Repository Service

The Image Repository service ("The Storage") hosts the signed metadata and
binary firmware images. It is responsible for serving encrypted payloads
to vehicles.

Integrates:
- E2E Encryption (Phase 2)
"""

from fastapi import FastAPI, HTTPException, Response
from typing import Dict, Any, Optional
import json

from src.security.e2e_encryption import E2EEncryption
from src.uptane.metadata import RootMetadata, SnapshotMetadata, TimestampMetadata
from src.crypto.ecc_core import ECCCore, ECCCurve

app = FastAPI(title="SecureEV-OTA Image Repository")

# Initialize Crypto
ecc = ECCCore()
e2e = E2EEncryption()
repo_key = ecc.generate_keypair()

# Mock Storage
METADATA_STORE = {
    "root": RootMetadata(expires="2027-01-01", version=1),
    "snapshot": SnapshotMetadata(expires="2026-02-01", version=1),
    "timestamp": TimestampMetadata(expires="2026-01-25", version=1)
}

FIRMWARE_STORE = {
    "firmware_v2.0.bin": b"BINARY_FIRMWARE_CONTENT_V2.0"
}


@app.get("/metadata/{role}")
async def get_metadata(role: str):
    """
    Serve standardized Uptane metadata (Root, Snapshot, Timestamp).
    """
    if role not in METADATA_STORE:
        raise HTTPException(status_code=404, detail="Metadata role not found")
    
    metadata = METADATA_STORE[role]
    # In a real system, these would be pre-signed.
    # Here, we sign on the fly for the demo if not already signed.
    if not metadata.signatures:
        metadata.sign(repo_key, ecc)
        
    return metadata.to_dict()


@app.get("/targets/{filename}")
async def get_target(filename: str, vehicle_pub_key: Optional[str] = None):
    """
    Serve firmware image. Use E2E encryption if vehicle key provided.
    
    Args:
        filename: Name of the firmware file
        vehicle_pub_key: Hex string of vehicle's ephemeral public key (for E2E)
    """
    if filename not in FIRMWARE_STORE:
        raise HTTPException(status_code=404, detail="File not found")
        
    data = FIRMWARE_STORE[filename]
    
    # If encryption is requested (Phase 2)
    if vehicle_pub_key:
        try:
            from src.crypto.ecc_core import public_key_from_bytes, ECCCurve
            
            # 1. Parse Vehicle Key
            vehicle_key_obj = public_key_from_bytes(
                bytes.fromhex(vehicle_pub_key), 
                ECCCurve.SECP256R1
            )
            
            # 2. Ephemeral Key and Encryption
            # Use high-level API which handles derivation
            server_priv, server_pub = e2e.generate_ephemeral_keypair()
            
            # Legacy expected metadata in the envelope
            metadata_dict = {"filename": filename}
            
            package = e2e.encrypt(
                plaintext=data,
                our_private_key=server_priv,
                peer_public_key=vehicle_key_obj,
                additional_data=json.dumps(metadata_dict).encode()
            )
            
            # Return JSON envelope with encryption metadata
            response_data = package.to_dict()
            response_data["metadata"] = metadata_dict
            
            return response_data
            
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Encryption failed: {str(e)}")
            
    # Plain download (Legacy/Insecure mode)
    return Response(content=data, media_type="application/octet-stream")


@app.get("/")
async def root():
    return {"service": "SecureEV-OTA Image Repository", "status": "online"}
