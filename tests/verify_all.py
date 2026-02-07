"""
SecureEV-OTA: Complete End-to-End Verification Script

This script verifies all phases of the project are working together:
- Phase 1: Crypto Foundation
- Phase 2: Security Layer
- Phase 3: Protocol Implementation
- Phase 4: Backend Services
- Phase 5: Vehicle Client
- Phase 6: Simulation
"""

import asyncio
import httpx
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.ecc_core import ECCCore, ECCCurve
from src.security.encryption import E2EEncryption
from src.security.dos_protection import DoSProtection, TokenBucket
from src.uptane.metadata import TargetsMetadata, RootMetadata

DIRECTOR_URL = "http://localhost:8000"
IMAGE_REPO_URL = "http://localhost:8001"

class VerificationResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []
    
    def ok(self, name: str, details: str = ""):
        self.passed += 1
        self.results.append(("✅", name, details))
        print(f"  ✅ {name}: {details}")
    
    def fail(self, name: str, error: str):
        self.failed += 1
        self.results.append(("❌", name, error))
        print(f"  ❌ {name}: {error}")
    
    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Results: {self.passed}/{total} passed")
        return self.failed == 0


def verify_phase1_crypto(result: VerificationResult):
    """Verify Phase 1: Crypto Foundation"""
    print("\n📦 Phase 1: Crypto Foundation")
    
    try:
        ecc = ECCCore(ECCCurve.SECP256R1)
        keypair = ecc.generate_keypair()
        result.ok("Key generation", f"Key ID: {keypair.key_id[:8]}...")
    except Exception as e:
        result.fail("Key generation", str(e))
        return
    
    try:
        message = b"SecureEV-OTA test message"
        signature = ecc.sign(keypair.private_key, message, keypair.key_id)
        result.ok("ECDSA signing", f"Signature length: {len(signature.signature)} bytes")
    except Exception as e:
        result.fail("ECDSA signing", str(e))
        return
    
    try:
        is_valid = ecc.verify(keypair.public_key, message, signature.signature)
        if is_valid:
            result.ok("ECDSA verification", "Signature verified")
        else:
            result.fail("ECDSA verification", "Invalid signature")
    except Exception as e:
        result.fail("ECDSA verification", str(e))


def verify_phase2_security(result: VerificationResult):
    """Verify Phase 2: Security Layer"""
    print("\n🔒 Phase 2: Security Layer")
    
    try:
        ecc = ECCCore()
        e2e = E2EEncryption()
        
        # Server and client keypairs
        server_kp = ecc.generate_keypair()
        client_kp = ecc.generate_keypair()
        
        # Derive session keys
        server_session = e2e.establish_session_key(server_kp.private_key, client_kp.public_key)
        client_session = e2e.establish_session_key(client_kp.private_key, server_kp.public_key)
        
        if server_session == client_session:
            result.ok("ECDH key exchange", f"Session key: {server_session[:8].hex()}...")
        else:
            result.fail("ECDH key exchange", "Session keys don't match")
            return
    except Exception as e:
        result.fail("ECDH key exchange", str(e))
        return
    
    try:
        plaintext = b"Firmware update payload v2.1.0"
        nonce, ciphertext = e2e.encrypt_payload(plaintext, server_session)
        decrypted = e2e.decrypt_payload(ciphertext, nonce, client_session)
        
        if decrypted == plaintext:
            result.ok("AES-GCM encryption", f"Encrypted {len(plaintext)} -> {len(ciphertext)} bytes")
        else:
            result.fail("AES-GCM encryption", "Decryption mismatch")
    except Exception as e:
        result.fail("AES-GCM encryption", str(e))
    
    try:
        dos = DoSProtection()
        # Should allow first request
        if dos.is_request_allowed("test-vehicle"):
            result.ok("DoS rate limiting", "Request allowed within limits")
        else:
            result.fail("DoS rate limiting", "Request incorrectly blocked")
    except Exception as e:
        result.fail("DoS rate limiting", str(e))


def verify_phase3_protocol(result: VerificationResult):
    """Verify Phase 3: Protocol"""
    print("\n📋 Phase 3: Protocol Implementation")
    
    try:
        ecc = ECCCore()
        keypair = ecc.generate_keypair()
        
        targets = TargetsMetadata(expires="2026-12-31T23:59:59Z", version=1)
        targets.add_target("firmware.bin", "abc123", 1024, "EV-MODEL-S")
        targets.sign(keypair, ecc)
        
        signed_data = targets.to_dict()
        if "signed" in signed_data and "signatures" in signed_data:
            result.ok("Metadata signing", f"Signatures: {len(signed_data['signatures'])}")
        else:
            result.fail("Metadata signing", "Invalid metadata structure")
    except Exception as e:
        result.fail("Metadata signing", str(e))


async def verify_phase4_backend(result: VerificationResult):
    """Verify Phase 4: Backend Services"""
    print("\n🖥️  Phase 4: Backend Services")
    
    async with httpx.AsyncClient() as client:
        # Director health
        try:
            resp = await client.get(f"{DIRECTOR_URL}/")
            data = resp.json()
            if data.get("status") == "online":
                result.ok("Director health", f"Public key: {data.get('public_key', '')[:16]}...")
            else:
                result.fail("Director health", f"Unexpected: {data}")
        except Exception as e:
            result.fail("Director health", str(e))
        
        # Image Repo health
        try:
            resp = await client.get(f"{IMAGE_REPO_URL}/")
            data = resp.json()
            if data.get("status") == "online":
                result.ok("Image Repo health", f"Public key: {data.get('public_key', '')[:16]}...")
            else:
                result.fail("Image Repo health", f"Unexpected: {data}")
        except Exception as e:
            result.fail("Image Repo health", str(e))


async def verify_phase5_client(result: VerificationResult):
    """Verify Phase 5: Vehicle Client"""
    print("\n🚗 Phase 5: Vehicle Client")
    
    async with httpx.AsyncClient() as client:
        # Register vehicle
        try:
            payload = {
                "vehicle_id": "VIN-VERIFY-001",
                "ecu_id": "PRIMARY-ECU-VERIFY",
                "public_key": "a" * 64,
                "hardware_id": "EV-MODEL-S"
            }
            resp = await client.post(f"{DIRECTOR_URL}/register", json=payload)
            if resp.status_code == 200:
                result.ok("Vehicle registration", resp.json().get("message", ""))
            else:
                result.fail("Vehicle registration", resp.text)
        except Exception as e:
            result.fail("Vehicle registration", str(e))
        
        # Get manifest
        try:
            resp = await client.get(f"{DIRECTOR_URL}/manifest/VIN-VERIFY-001")
            if resp.status_code == 200:
                data = resp.json()
                if "signed" in data:
                    result.ok("Manifest retrieval", "Signed targets received")
                else:
                    result.ok("Manifest retrieval", data.get("message", "No updates"))
            else:
                result.fail("Manifest retrieval", resp.text)
        except Exception as e:
            result.fail("Manifest retrieval", str(e))


async def verify_phase6_simulation(result: VerificationResult):
    """Verify Phase 6: Simulation"""
    print("\n🎮 Phase 6: Simulation")
    
    try:
        from src.simulation.agent import VehicleAgent
        from src.simulation.manager import FleetManager
        result.ok("Simulation imports", "FleetManager and VehicleAgent available")
    except ImportError as e:
        result.fail("Simulation imports", str(e))


async def run_full_verification():
    """Run all verification checks."""
    print("="*60)
    print("SecureEV-OTA Full Integration Verification")
    print("="*60)
    
    result = VerificationResult()
    
    # Phase 1-3: Offline crypto/protocol tests
    verify_phase1_crypto(result)
    verify_phase2_security(result)
    verify_phase3_protocol(result)
    
    # Phase 4-6: Online service tests
    await verify_phase4_backend(result)
    await verify_phase5_client(result)
    await verify_phase6_simulation(result)
    
    success = result.summary()
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_full_verification())
    sys.exit(exit_code)
