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
import httpx

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
            image_repo_url=image_repo_url,
            director_public_key_hex=director_pub_key
        )

    async def run(self):
        """Lifecycle loop."""
        self.running = True
        self._report_status("STARTING")

        try:
            # 1. Registration Phase - Staggered to avoid thundering herd
            # Use exponential distribution (mean 2s) with hard cap at 10s
            await asyncio.sleep(min(random.expovariate(0.5), 10.0))
            await self.ecu.register()
            logger.info(f"[{self.id}] Registered successfully via Director")
            self._report_status("REGISTERED")

            # 2. Polling Loop
            while self.running:
                # Random poll interval (simulating 1-10 seconds for demo, normally hours)
                # Use uniform for more predictable spread
                await asyncio.sleep(random.uniform(1.0, 10.0))
                
                try:
                    self._report_status("POLLING")
                    logger.info(f"[{self.id}] Polling for updates...")
                    await self.ecu.poll_for_updates()
                    logger.info(f"[{self.id}] Update check complete - System up to date")
                    self._report_status("IDLE (Updated)")
                except httpx.RequestError as e:
                    # Transient network error — mark as network issue and backoff
                    self._report_status(f"NETWORK_ERROR: {str(e)}")
                    logger.warning(f"[{self.id}] Network error during update check: {e}")
                    await asyncio.sleep(2.0)
                except UpdateError as e:
                    # If the UpdateError contains a retry_after attribute, back off accordingly
                    retry_after = getattr(e, "retry_after", None)
                    if retry_after is not None:
                        try:
                            retry_seconds = float(retry_after)
                            self._report_status(f"RATE_LIMITED: retry after {retry_seconds}s")
                            logger.warning(f"[{self.id}] Rate limited, backing off for {retry_seconds}s")
                            await asyncio.sleep(retry_seconds)
                        except (ValueError, TypeError):
                            logger.warning(f"[{self.id}] Rate limited but retry_after "
                                           f"'{retry_after}' is not numeric, using 5s default")
                            self._report_status("RATE_LIMITED: retry after 5s (parse error)")
                            await asyncio.sleep(5.0)
                    else:
                        self._report_status(f"ERROR: {str(e)}")
                        logger.error(f"[{self.id}] Update failed: {e}")
                except Exception as e:
                    self._report_status(f"CRASH: {str(e)}")
                    logger.exception(f"[{self.id}] Critical failure: {e}")
                    
        except asyncio.CancelledError:
            self._report_status("STOPPED")
        finally:
            self.running = False
            # Close HTTP client to release connections
            await self.ecu.close()

    def stop(self):
        self.running = False

    def _report_status(self, status: str):
        if self.status_callback:
            self.status_callback(self.id, status)
