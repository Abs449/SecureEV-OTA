
import asyncio
import random
import logging
from typing import Dict, Optional
from src.client.ecu import PrimaryECU, UpdateError

logger = logging.getLogger("VehicleAgent")

class VehicleAgent:
    """
    Simulation wrapper around the PrimaryECU.
    Manages the lifecycle loop and simulates network conditions.
    """
    def __init__(self, 
                 vehicle_id: str, 
                 director_url: str, 
                 image_repo_url: str, 
                 director_public_key_hex: str, 
                 config: Dict = None):
        
        self.vehicle_id = vehicle_id
        # Initialize the real ECU logic
        self.ecu = PrimaryECU(
            vehicle_id=vehicle_id,
            director_url=director_url,
            unknown_image_repo_url=image_repo_url,
            director_public_key_hex=director_public_key_hex
        )
        self.config = config or {"network_latency_ms": 0, "check_interval_sec": 5}
        self.state = "IDLE"

    async def run_lifecycle(self, duration_sec: Optional[int] = None):
        """
        Simulate the vehicle lifecycle.
        
        Args:
            duration_sec: Optional duration to run. If None, runs forever.
        """
        start_time = asyncio.get_event_loop().time()
        
        # 1. Register first
        try:
            self.state = "REGISTERING"
            await self._simulate_latency()
            await self.ecu.register()
            self.state = "REGISTERED"
        except Exception as e:
            logger.error(f"Agent {self.vehicle_id} failed to register: {e}")
            self.state = "ERROR"
            return

        while True:
            # Check duration
            if duration_sec and (asyncio.get_event_loop().time() - start_time > duration_sec):
                break

            # Random jitter before next check
            await asyncio.sleep(random.uniform(0.5, 2.0))
            
            # Configured Check Interval
            await asyncio.sleep(self.config.get("check_interval_sec", 5))
            
            # Network Latency Simulation
            await self._simulate_latency()
            
            try:
                self.state = "CHECKING_UPDATES"
                # Note: pollution of internal state might be needed for "UPDATING"
                # For now, we wrap the call.
                await self.ecu.poll_for_updates()
                self.state = "IDLE"
            except UpdateError as e:
                logger.warning(f"Agent {self.vehicle_id} update error: {e}")
                self.state = "UPDATE_FAILED"
            except Exception as e:
                logger.error(f"Agent {self.vehicle_id} crashed: {e}")
                self.state = "CRASHED"
                await asyncio.sleep(5) # Backoff after crash

    async def _simulate_latency(self):
        latency_ms = self.config.get("network_latency_ms", 0)
        if latency_ms > 0:
            await asyncio.sleep(latency_ms / 1000.0)
