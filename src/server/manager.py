"""
SecureEV-OTA: Backend Manager Utility

This script provides administrative functions to manage the OTA backend,
such as uploading new firmware and registering vehicles.
"""

import requests
import hashlib
import os
import sys

def upload_firmware(filename, hardware_id, content=None):
    """Generate and upload a firmware image to the Image Repo."""
    if content is None:
        # Generate dummy firmware with some random data
        content = os.urandom(1024) + f" Firmware for {hardware_id} v1.0".encode()
    
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Upload to Image Repo
    # We use the /upload endpoint we created in image_repo.py
    try:
        response = requests.post(
            f"http://localhost:8001/upload?filename={filename}",
            data=content
        )
        if response.status_code == 200:
            print(f"Successfully uploaded {filename} to Image Repo")
            print(f"Hash: {file_hash}")
        else:
            print(f"Failed to upload: {response.text}")
    except Exception as e:
        print(f"Error connecting to Image Repo: {e}")

def register_test_vehicle():
    """Register a sample vehicle with the Director."""
    payload = {
        "vehicle_id": "VIN123456789",
        "ecu_id": "PRIMARY-ECU-01",
        "public_key": "abc123def", # Simplified for demo
        "hardware_id": "EV-MODEL-S"
    }
    
    try:
        response = requests.post("http://localhost:8000/register", json=payload)
        if response.status_code == 200:
            print(f"Successfully registered vehicle VIN123456789")
        else:
            print(f"Failed to register: {response.text}")
    except Exception as e:
        print(f"Error connecting to Director: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manager.py [upload|register]")
        sys.exit(1)
        
    cmd = sys.argv[1]
    if cmd == "upload":
        upload_firmware("firmware-v210.bin", "EV-MODEL-S")
    elif cmd == "register":
        register_test_vehicle()
    else:
        print(f"Unknown command: {cmd}")
