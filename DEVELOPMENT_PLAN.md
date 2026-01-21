# Development Plan: SecureEV-OTA

> **Current Status**: Phase 2 (Security Layer) is **COMPLETE**.
> **Next Objective**: Begin Phase 3 (Protocol Implementation).

This document outlines the step-by-step implementation plan for continuing development of the SecureEV-OTA framework. It translates the high-level roadmap into actionable engineering tasks.

---

## 📅 Roadmap Overview

| Phase | Focus | Estimated Duration | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Crypto Foundation** | Week 1-2 | ✅ **DONE** |
| **Phase 2** | **Security Layer** | Week 3-4 | ✅ **DONE** |
| **Phase 3** | **Protocol Implementation** | Week 5-6 | ⏩ **NEXT** |
| **Phase 4** | **Backend Services** | Week 7-8 | 📅 Planned |
| **Phase 5** | **Vehicle Client** | Week 9-10 | 📅 Planned |
| **Phase 6** | **Simulation & Polish** | Week 11-12 | 📅 Planned |

---

## ⏩ Phase 2: Security Layer Implementation

**Goal**: Implement the mandatory security features that sit on top of the crypto foundation: End-to-End (E2E) Encryption and Denial-of-Service (DoS) Protection.

### 2.1 End-to-End Encryption Module
*Protect firmware confidentiality from CDNs and proxies.*

- [ ] **Create `src/security/encryption.py`**
    - [ ] Implement `E2EEncryption` class.
    - [ ] Integrate `ECDHKeyExchange` from Phase 1.
    - [ ] Implement `establish_session(server_priv, client_pub)` -> `shared_secret`.
    - [ ] Implement `encrypt_payload(data, key)` using AES-256-GCM.
    - [ ] Implement `decrypt_payload(data, key)` verifying the GCM tag.
- [ ] **Tests**
    - [ ] Verify that data encrypted by "Server" can be decrypted by "Vehicle".
    - [ ] Verify that changed ciphertext fails decryption (integrity check).

### 2.2 DoS Protection Module
*Prevent resource exhaustion attacks.*

- [ ] **Create `src/security/dos_protection.py`**
    - [ ] Implement `TokenBucket` class for rate limiting.
    - [ ] Implement `RequestValidator` to check manifest signatures *before* processing.
    - [ ] Add `check_request_eligibility(vehicle_id, timestamp)` method.
- [ ] **Tests**
    - [ ] Simulate rapid-fire requests and verify rejection.
    - [ ] Verify legitimate requests pass through.

---

## 📅 Phase 3: Protocol Integration

**Goal**: Implement the enhanced Uptane protocol messages and metadata handling.

### 3.1 Metadata Architecture
- [ ] **Create `src/protocol/metadata.py`**
    - [ ] Define JSON schemas for `Root`, `Targets`, `Snapshot`, and `Timestamp` metadata.
    - [ ] Implement `MetadataBuilder` for creating signed metadata files.
    - [ ] Use `ECCCore.sign` (Phase 1) to apply signatures to JSON structures.

### 3.2 Protocol Logic
- [ ] **Create `src/protocol/uptane.py`**
    - [ ] Implement `UptaneClient` class for vehicle logic.
    - [ ] Implement `verify_metadata_chain(root, targets, snapshot, timestamp)`.
    - [ ] Integrate `BatchECDSAVerifier` (Phase 1) for validating lists of targets.

---

## 📅 Phase 4: Backend Services

**Goal**: Build the HTTP API servers for the Image and Director repositories.

### 4.1 Director Repository (The "Brain")
- [ ] **Create `src/server/director.py`**
    - [ ] Setup FastAPI project.
    - [ ] Endpoint `/register_vehicle`: Register ECUs and public keys.
    - [ ] Endpoint `/check_updates`: Generate and sign custom manifests for vehicles.
    - [ ] Integrate `DoSProtection` (Phase 2).

### 4.2 Image Repository (The "Storage")
- [ ] **Create `src/server/image_repo.py`**
    - [ ] Endpoint `/get_metadata`: Serve generic targets metadata.
    - [ ] Endpoint `/download_image`: Serve encrypted firmware blobs.
    - [ ] Integrate `E2EEncryption` (Phase 2) to encrypt on-the-fly or pre-encrypt.

---

## 📅 Phase 5: Client & Simulation

**Goal**: Create a realistic simulation of a vehicle fleet to prove the system works.

### 5.1 Vehicle Client
- [ ] **Create `src/client/vehicle.py`**
    - [ ] Implement `PrimaryECU` class.
    - [ ] Function `poll_for_updates()`: Contact Director.
    - [ ] Function `process_update_bundle()`: Verify signatures -> Decrypt -> Install.
    - [ ] Implement `SecondaryECU` logic (Lightweight verification).

### 5.2 Fleet Simulator
- [ ] **Create `src/simulation/fleet.py`**
    - [ ] Script to spin up 100+ simulated `PrimaryECU` instances.
    - [ ] Trigger simultaneous update requests to test scalability.

---

## 🚀 How to Execute This Plan

To continue development, follow these steps:

1.  **Checkout the `main` branch** to ensure you are on the latest Phase 1 code.
2.  **Create a feature branch** for Phase 2: `git checkout -b feature/phase2-security`.
3.  **Start with Task 2.1** (Encryption) as it has no dependencies other than Phase 1.
4.  **Write tests first!** Create `tests/test_security.py` before writing the implementation.
5.  **Commit often**: One commit per solved sub-task.

### Suggested Command Sequence for Next Session:

```bash
# 1. Create the security module structure
mkdir src/security
touch src/security/__init__.py src/security/encryption.py src/security/dos_protection.py

# 2. Create the test file
touch tests/test_security.py

# 3. Begin implementing E2EEncryption in src/security/encryption.py
```
