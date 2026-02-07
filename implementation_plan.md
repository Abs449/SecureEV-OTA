# Implementation Plan: SecureEV-OTA Phase 3 & 4

> **Status Update**: 
> - Phase 1 (Crypto Foundation): **COMPLETE**
> - Phase 2 (Security Layer): **COMPLETE** (Verified via `tests/test_security.py`)
> - Phase 3 (Protocol): **PARTIAL** (Metadata structures exist, client logic needing refinement)
> - Phase 4 (Backend): **PENDING**

This plan outlines the steps to complete the Protocol layer and build the Backend Services (Director and Image Repository).

## User Review Required
> [!IMPORTANT]
> **Key Management**: The current implementation uses ephemeral keys for E2E encryption. For the full Uptane flow, we need to implement the **Key Management Service** / persistent key storage for the Director and Image Repo to sign metadata. We will use local file-based keystores for this development phase.

## Proposed Changes

### Phase 3: Protocol Refinement (finish `src/protocol`)

The current `uptane_enhanced.py` contains mock logic. we need to formalize the verification and handling.

#### [MODIFY] [src/protocol/uptane_enhanced.py](file:///e:/Projects/Secure%20OTA/SecureEV-OTA/src/protocol/uptane_enhanced.py)
- Refine `request_update` to handle real metadata verification failures.
- Implement proper key lookup from `trusted_keys`.
- Add `SecondaryECU` logic support.

### Phase 4: Backend Services (create `src/server`)

We need a FastAPI based server to act as the Director and Image Repository.

#### [NEW] [src/server/schemas.py](file:///e:/Projects/Secure%20OTA/SecureEV-OTA/src/server/schemas.py)
- Pydantic models for API requests/responses (Vehicle Check-in, Manifest).

#### [NEW] [src/server/director.py](file:///e:/Projects/Secure%20OTA/SecureEV-OTA/src/server/director.py)
- **FastAPI App**: The "Director" service.
- **Endpoint**: `POST /vehicle/checkin`
    - Receives VIN and basic telemetry.
    - Determines if an update is needed.
    - Generates and signs `root.json` or `targets.json` (Director metadata).
- **Integration**: Uses `src.security.dos_protection` middleware.

#### [NEW] [src/server/image_repo.py](file:///e:/Projects/Secure%20OTA/SecureEV-OTA/src/server/image_repo.py)
- **FastAPI App**: The "Image Repository" service.
- **Endpoint**: `GET /metadata/{role}`
    - Serves signed metadata (`snapshot.json`, `timestamp.json`, `targets.json`).
- **Endpoint**: `GET /targets/{filename}`
    - Serves the *encrypted* firmware images.
    - Uses `src.security.e2e_encryption` to encrypt blobs on disk (or on-the-fly).

#### [NEW] [src/server/main.py](file:///e:/Projects/Secure%20OTA/SecureEV-OTA/src/server/main.py)
- Entry point to run both services (or mount them together) for development.

## Verification Plan

### Automated Tests
- Create `tests/test_protocol.py` to test `uptane_enhanced.py` logic with mocked network.
- Create `tests/test_server.py` using `TestClient` (FastAPI) to verify endpoints.

### Manual Verification
- Run the server: `python -m src.server.main`
- Run a simulation script (Phase 5) to connect and download an update.
