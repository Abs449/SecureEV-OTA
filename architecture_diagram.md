# SecureEV-OTA Absolute Architecture Diagram

Based on the exact structure and implementation of the `SecureEV-OTA` project, the following diagram maps the comprehensive architecture, detailing the deployment model, module interactions, and core components of both the OEM Cloud and the Electric Vehicle.

## Architecture Diagram

```mermaid
%%{init: {'theme': 'default', 'themeVariables': { 'background': '#ffffff', 'primaryTextColor': '#000000', 'lineColor': '#000000', 'primaryColor': '#ffffff', 'primaryBorderColor': '#000000', 'clusterBkg': '#ffffff', 'clusterBorder': '#000000', 'textColor': '#000000'}}}%%
graph TB
    subgraph SimulationEnv ["Testing & Fleet Simulation (simulation.py)"]
        FleetManager["Fleet Manager<br>(src/simulation/manager.py)"]
        subgraph VirtualFleet ["Virtual Fleet"]
            Agent1["Vehicle Agent 1"]
            AgentN["Vehicle Agent 'N'"]
        end
        FleetManager -- Spawns/Controls --> Agent1
        FleetManager -- Spawns/Controls --> AgentN
    end

    subgraph OEMCloud ["OEM Cloud Backend (src/server)"]
        DirectorRepo["Director Repository<br>(Targeting & Metadata)<br>Port 8000"]
        ImageRepo["Image Repository<br>(Encrypted Firmware)<br>Port 8001"]
        
        subgraph SecurityLayer ["Security / DoS Layer (src/security)"]
            DoS["DoS Protection<br>(Token Bucket Rate Limiting)"]
            E2EServer["End-to-End Encryption<br>(AES-256-GCM + ECDH)"]
        end
        
        DirectorRepo -->|Uses| DoS
        ImageRepo -->|Uses| E2EServer
    end

    subgraph EV ["Electric Vehicle Client (src/client)"]
        PrimaryECU["Primary ECU<br>(src/client/ecu.py)"]
        SecondaryECU["Secondary ECUs"]
        
        subgraph ClientSecurity ["Client Protocol & Crypto"]
            UptaneClient["Uptane Client Module<br>(src/uptane)"]
            CryptoCore["Crypto Core<br>(src/crypto)"]
            E2EClient["Decryption Engine<br>(src/security)"]
        end
        
        PrimaryECU -->|Verifies Metadata| UptaneClient
        PrimaryECU -->|Decrypts| E2EClient
        UptaneClient -->|Signature Verification| CryptoCore
        E2EClient -->|AES/ECDH| CryptoCore
        
        PrimaryECU -->|Distributes Update| SecondaryECU
    end

    subgraph CryptoModules ["Crypto Module Details (src/crypto)"]
        BaseECC["ECC Core<br>(ECDSA/ECDH)"]
        Lightweight["Lightweight ECC<br>(Montgomery Ladder)"]
        BatchVerifier["Batch Verifier<br>(KGLP Algorithm)"]
        HybridPQC["Hybrid PQC<br>(ECDSA + ML-DSA)"]
        
        BaseECC --- Lightweight
        BaseECC --- BatchVerifier
        BaseECC --- HybridPQC
    end

    %% Network Connections
    Agent1 -. Wraps .-> PrimaryECU
    
    DirectorRepo -- "Signed Metadata (JSON)<br>over HTTP" --> PrimaryECU
    ImageRepo -- "Encrypted Firmware Blob<br>over HTTP" --> PrimaryECU
    PrimaryECU -- "Register / Polling" --> DirectorRepo

    %% Styling for White Background and Black Borders
    style FleetManager fill:#ffffff,stroke:#000000,color:#000000
    style Agent1 fill:#ffffff,stroke:#000000,color:#000000
    style AgentN fill:#ffffff,stroke:#000000,color:#000000
    style DirectorRepo fill:#ffffff,stroke:#000000,color:#000000
    style ImageRepo fill:#ffffff,stroke:#000000,color:#000000
    style DoS fill:#ffffff,stroke:#000000,color:#000000
    style E2EServer fill:#ffffff,stroke:#000000,color:#000000
    style PrimaryECU fill:#ffffff,stroke:#000000,color:#000000
    style SecondaryECU fill:#ffffff,stroke:#000000,color:#000000
    style UptaneClient fill:#ffffff,stroke:#000000,color:#000000
    style CryptoCore fill:#ffffff,stroke:#000000,color:#000000
    style E2EClient fill:#ffffff,stroke:#000000,color:#000000
    style BaseECC fill:#ffffff,stroke:#000000,color:#000000
    style Lightweight fill:#ffffff,stroke:#000000,color:#000000
    style BatchVerifier fill:#ffffff,stroke:#000000,color:#000000
    style HybridPQC fill:#ffffff,stroke:#000000,color:#000000

    style SimulationEnv fill:#f9f9f9,stroke:#000000,color:#000000
    style OEMCloud fill:#f9f9f9,stroke:#000000,color:#000000
    style EV fill:#f9f9f9,stroke:#000000,color:#000000
    style CryptoModules fill:#f9f9f9,stroke:#000000,color:#000000
    style SecurityLayer fill:#eeeeee,stroke:#000000,color:#000000
    style VirtualFleet fill:#eeeeee,stroke:#000000,color:#000000
    style ClientSecurity fill:#eeeeee,stroke:#000000,color:#000000
```

---

## Component Mapping Breakdown

### 1. OEM Cloud Backend (Server)
Stored in `src/server/`, this represents the OEM's update infrastructure. 
- **Director (`director.py`)**: Runs on port 8000. It manages vehicle registrations, provides public keys for trust bootstrapping, and generates tailored update metadata for specific vehicles.
- **Image Repository (`image_repo.py`)**: Runs on port 8001. It is the storage location for `E2E encrypted` firmware blobs securely uploaded by the OEM.
- **Security Layer (`src/security/`)**: Wraps backend interactions. Uses `dos_protection.py` to prevent DDoS on update requests via advanced Token Bucket rate limiting, and `e2e_encryption.py` to securely pack firmware using ECDH-derived AES-GCM algorithms.

### 2. Electric Vehicle Client
Stored in `src/client/`, representing the primary edge device (ECU) inside the actual vehicle.
- **Primary ECU (`ecu.py`)**: The main interface connecting to the OEM cloud. It coordinates the update lifecycle: Polling the Director, downloading firmware from the Image Repo, verifying Uptane-signed metadata, decrypting payloads, and installing.
- **Uptane Layer (`src/uptane/`)**: Handles the Uptane-standardized metadata formats for Root, Targets, and Snapshots, guaranteeing no malicious downgrades or mix-and-match attacks succeed.

### 3. Cryptographic Core
Stored in `src/crypto/`, this highly modular package is heavily referenced by both the Cloud and the Vehicle.
- **ECC Core (`ecc_core.py`)**: The P-256 standard foundation for ECDSA and ECDH.
- **Lightweight ECC (`lightweight_ecc.py`)**: Utilizes point compression and Montgomery Ladder to reduce the ECU memory footprint of cryptographic checks by 50%.
- **Batch Verification (`batch_verifier.py`)**: Optimizes Cloud-side verification of incoming fleet data using KGLP algorithm.
- **Hybrid PQC (`hybrid_pqc.py`)**: An absolute future-proofing mechanism using classical ECDSA + post-quantum algorithms (ML-DSA) to sign and verify.

### 4. Fleet Simulation
Stored in `simulation.py` and `src/simulation/`.
- **Fleet Manager (`manager.py`)**: Harnesses `asyncio` to spawn hundreds of localized instances of vehicle clients (`VehicleAgent`). Demonstrates mass-concurrency, resilience, and real-time Dashboard metrics. 
- **Vehicle Agents**: Wrappers that use actual instances of `PrimaryECU`, connecting loop-backed HTTP traffic securely to the Director and Image repositories on the local testing network.
