# Simulation Design: SecureEV-OTA Fleet Framework

This document details the architecture, technology stack, and implementation strategy for the **Phase 5/6 Simulation**, which validates the SecureEV-OTA framework at scale.

## 1. Objectives

1.  **Scalability**: Simulate 1,000+ connected vehicles on a single developer workstation.
2.  **Realism**: Emulate realistic network latency, packet loss, and ECU processing times.
3.  **Attack Injection**: Systematically test security defenses against simulated active attackers.
4.  **Observability**: Real-time metrics on update success rates and detection events.

## 2. Technology Stack

We will stick to a **Pure Python** stack for the core logic to maximize code reuse from the main project, augmented by lightweight containerization for isolation.

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Concurrency** | **Python `asyncio`** | Allows thousands of lightweight "Vehicle Agents" to run concurrently in a single process without the overhead of OS threads. |
| **Networking** | **`aiohttp`** | Asynchronous HTTP client/server for non-blocking communication between Vehicles and Repositories. |
| **Containerization** | **Docker** | Used to package the "Server" (Director/Image Repo) separately from the "Fleet" (Simulation). |
| **Metrics** | **Prometheus Client** | Vehicles expose `/metrics` for real-time dashboarding. |
| **Orchestration** | **Python Script** | A custom `fleet_manager.py` is simpler and more flexible than Kubernetes for this specific scale. |

## 3. Architecture

The simulation follows a **Centralized Command / Distributed Execution** model.

```mermaid
graph TD
    Manager[Fleet Manager<br>(Python Process)]
    
    subgraph "Simulated Fleet (asyncio loop)"
        V1[Vehicle Agent 1]
        V2[Vehicle Agent 2]
        V3[Vehicle Agent ...N]
        Evil[Attacker Agent]
    end
    
    subgraph "Infrastructure (Docker)"
        Director[Director Repo]
        Image[Image Repo]
    end

    Manager -- Spawns/Controls --> V1
    Manager -- Spawns/Controls --> V2
    Manager -- Injects Faults --> V3
    
    V1 -- Polls/Downloads --> Director
    V1 -- Polls/Downloads --> Image
    
    Evil -- Sends Bad Signatures --> V1
    
    style Manager fill:#d1c4e9,stroke:#512da8
    style Director fill:#bbdefb,stroke:#1565c0
    style V1 fill:#c8e6c9,stroke:#2e7d32
    style Evil fill:#ffcdd2,stroke:#c62828
```

## 4. Implementation Details

### 4.1 The Vehicle Agent (`VehicleAgent`)
This is a lightweight wrapper around the `PrimaryECU` class. It mocks the hardware interfaces (storage, CAN bus) but runs the **real** cryptographic and protocol logic.

```python
class VehicleAgent:
    def __init__(self, vehicle_id, config):
        self.ecu = PrimaryECU(id=vehicle_id)  # Real core logic
        self.state = "IDLE"
        self.network_condition = config.network_profile # e.g., "5G", "Spotty_4G"

    async def run_lifecycle(self):
        while True:
            # 1. Simulate randomized poll interval (jitter)
            await asyncio.sleep(random.uniform(60, 300))
            
            # 2. Simulate Network Latency
            delay = self.get_network_delay()
            await asyncio.sleep(delay)
            
            # 3. Perform Update Check
            try:
                await self.ecu.poll_for_updates()
            except SecurityException as e:
                self.report_attack(e)
```

### 4.2 The Fleet Manager (`fleet_manager.py`)
This script is the entry point. It creates the event loop and spawns thousands of agent tasks.

```python
async def main():
    # 1. Configuration
    target_vehicle_count = 1000
    
    # 2. Spawn Fleet
    tasks = []
    for i in range(target_vehicle_count):
        agent = VehicleAgent(id=uuid.uuid4(), config=PROFILE_Standard)
        tasks.append(asyncio.create_task(agent.run_lifecycle()))
        
    # 3. Monitoring Loop
    while True:
        draw_dashboard(active=len(tasks), updating=count_updating())
        await asyncio.sleep(1)
```

### 4.3 Handling "Simulated Hardware"
Since we don't have real flash memory, we mock the `Install` phase:
- **Flash Write**: `await asyncio.sleep(write_size / write_speed)`
- **Reboot**: `await asyncio.sleep(boot_time)`
- **Verification**: CPU-bound crypto operations (ECDSA verify) are run in a `ProcessPoolExecutor` so they don't block the main asyncio loop.

## 5. Building and Managing

### Build Process
1.  **Dockerize the Server**: Create a `Dockerfile` for the Director/Image repositories.
2.  **Dockerize the Simulation**: Create a `Dockerfile` for the `fleet_manager.py`.

### Management Workflow
1.  **Start Infrastructure**: `docker-compose up -d director image_repo`
2.  **Launch Fleet**: `python src/simulation/fleet_manager.py --count 500`
3.  **Inject Chaos**: The manager listens for CLI commands:
    - `> inject --target v-123 --attack rollback` -> Forces Vehicle 123 to receive an old manifest.
    - `> network --global --latency 500ms` -> Simulates a global network slowdown.
4.  **Analyze**: View real-time stats in the terminal UI or Grafana.

## 6. Development Strategy

1.  **Mock Interfaces First**: Create abstract base classes for `Storage` and `Network` so the core logic doesn't know it's being simulated.
2.  **Small Scale Test**: Run 5 agents to verify the async logic.
3.  **Scale Up**: Optimize memory usage (using `__slots__` in Python classes) to hit 1000+ agents.
