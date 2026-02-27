# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecureEV-OTA is a production-ready, hybrid ECC-based security framework enhancing the Uptane standard for Electric Vehicles. It provides secure Over-the-Air (OTA) updates with mandatory end-to-end encryption, DoS protection, and ECC-based digital signatures (ECDSA) with classical security.

## Common Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Start backend services (Windows)
./start_servers.ps1

# Or manually start each service:
uvicorn src.server.director:app --port 8000
uvicorn src.server.image_repo:app --port 8001

# Run fleet simulation (requires servers running)
python simulation.py

# Run all tests
pytest tests/
python tests/verify_all.py

# Run a single test
pytest tests/test_crypto.py -v

# Docker deployment
docker compose up --build -d
docker attach ota-simulation  # View simulation dashboard
```

## Architecture

The system implements a two-repository Uptane architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                     OEM Cloud Backend                        │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │    Director     │    │  Image Repo    │                 │
│  │   (port 8000)   │    │  (port 8001)   │                 │
│  │  Targeting &   │    │  Encrypted      │                 │
│  │  Signing       │    │  Firmware       │                 │
│  └────────┬────────┘    └────────┬────────┘                 │
│           │                      │                           │
│           └──────────┬───────────┘                           │
│                      ▼                                       │
│            ┌─────────────────┐                              │
│            │  DoS Protection │                              │
│            └────────┬────────┘                              │
└─────────────────────┼───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Electric Vehicle                          │
│  ┌─────────────────────────────────────────────────┐       │
│  │              Primary ECU (Uptane Client)         │       │
│  │  - Registers with Director                       │       │
│  │  - Fetches signed metadata                       │       │
│  │  - Downloads encrypted firmware                  │       │
│  │  - E2E decrypts with own private key            │       │
│  │  - Verifies integrity & installs               │       │
│  └─────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### Key Modules

| Module | Location | Purpose |
|--------|----------|---------|
| **Crypto Core** | `src/crypto/ecc_core.py` | ECDSA signing/verification, ECDH key exchange |
| **E2E Encryption** | `src/security/encryption.py` | AES-256-GCM with ECDH-derived session keys |
| **DoS Protection** | `src/security/dos_protection.py` | Token bucket rate limiting per vehicle |
| **Uptane Metadata** | `src/uptane/metadata.py` | Root, Targets, Snapshot, Timestamp metadata |
| **Director** | `src/server/director.py` | Vehicle registration, manifest generation (port 8000) |
| **Image Repo** | `src/server/image_repo.py` | Encrypted firmware storage (port 8001) |
| **Client** | `src/client/ecu.py` | Primary ECU implementation with verify/install |
| **Fleet Simulation** | `src/simulation/manager.py` | 50 concurrent vehicle simulation (default VEHICLE_COUNT = 50, configurable) with Rich TUI |

### Data Flow

1. **Registration**: Vehicle ECU generates keypair, registers with Director
2. **Update Check**: ECU polls Director for assigned targets (signed metadata)
3. **Download**: ECU fetches encrypted firmware from Image Repo (includes vehicle's pubkey)
4. **Decryption**: ECU derives session key via ECDH, decrypts with AES-256-GCM
5. **Installation**: ECU verifies hash against metadata, installs firmware

## Security Features

- **End-to-End Encryption**: ECDH + AES-256-GCM (not just transport layer)
- **Per-Session Ephemeral Keys**: Forward secrecy via ephemeral keypairs
- **DoS Resilience**: Token bucket rate limiting per vehicle ID
- **Metadata Signing**: Director signs all update manifests
- **Integrity Verification**: SHA-256 hash verification against metadata

## Environment Variables

```bash
DIRECTOR_URL=http://localhost:8000      # Default Director endpoint
IMAGE_REPO_URL=http://localhost:8001    # Default Image Repo endpoint
VEHICLE_COUNT=50                        # Number of simulated vehicles
```
