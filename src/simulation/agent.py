"""
SecureEV-OTA: Vehicle Agent (Simulation Wrapper)

This module wraps the PrimaryECU client logic for use in the simulation.
It adds:
- Asynchronous task management
- Randomized jitter/polling intervals
- Direct reporting of status/errors to the Fleet Manager
"""

import asyncio
import random
import logging
import uuid
from typing import Callable, Optional

from src.client.ecu import PrimaryECU, UpdateError

logger = logging.getLogger("VehicleAgent")

class VehicleAgent:
    """
    Represents a single simulated vehicle running in the fleet.
    """
    
    def __init__(self, 
                 director_url: str, 
                 image_repo_url: str, 
                 director_pub_key: str,
                 status_callback: Optional[Callable[[str, str], None]] = None):
        
        self.id = f"v-{str(uuid.uuid4())[:8]}"
        self.status_callback = status_callback
        self.running = False
        
        # Instantiate the real client logic
        self.ecu = PrimaryECU(
            vehicle_id=self.id,
            director_url=director_url,
            unknown_image_repo_url=image_repo_url,
            director_public_key_hex=director_pub_key
        )

    async def run(self):
        """Lifecycle loop."""
        self.running = True
        self._report_status("STARTING")
        
        try:
            # 1. Registration Phase (jittered to avoid thundering herd)
            await asyncio.sleep(random.uniform(0.1, 2.0))
            await self.ecu.register()
            self._report_status("REGISTERED")
            
            # 2. Polling Loop
            while self.running:
                # Random poll interval (simulating 1-5 seconds for demo, normally hours)
                await asyncio.sleep(random.uniform(1.0, 5.0))
                
                try:
                    self._report_status("POLLING")
                    await self.ecu.poll_for_updates()
                    self._report_status("IDLE (Updated)")
                except UpdateError as e:
                    self._report_status(f"ERROR: {str(e)}")
                    logger.error(f"Agent {self.id} error: {e}")
                except Exception as e:
                    self._report_status(f"CRASH: {str(e)}")
                    logger.exception(f"Agent {self.id} crashed")
                    
        except asyncio.CancelledError:
            self._report_status("STOPPED")
        finally:
            self.running = False

    def stop(self):
        self.running = False

    def _report_status(self, status: str):
        if self.status_callback:
            self.status_callback(self.id, status)
