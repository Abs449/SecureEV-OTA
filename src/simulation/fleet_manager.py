
import asyncio
import logging
import uuid
import httpx
import argparse
import sys
import time
from typing import List

# Fix import path to allow running as script from root
import os
sys.path.append(os.getcwd())

from src.simulation.vehicle_agent import VehicleAgent

# Configuration Constants
DEFAULT_DIRECTOR_URL = "http://localhost:8000"
DEFAULT_IMAGE_REPO_URL = "http://localhost:8001"
DEFAULT_VEHICLE_COUNT = 10

logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("FleetManager")

# Suppress noisy HTTP logs
logging.getLogger("httpx").setLevel(logging.WARNING)

async def fetch_director_key(url: str) -> str:
    """Fetch the director's public key to bootstrap trust."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{url}/key")
            resp.raise_for_status()
            return resp.json()["public_key"]
        except httpx.RequestError as e:
            logger.critical(f"Could not connect to Director at {url}: {e}")
            raise

async def main():
    parser = argparse.ArgumentParser(description="SecureEV-OTA Fleet Simulation")
    parser.add_argument("--count", type=int, default=DEFAULT_VEHICLE_COUNT, help="Number of vehicles to simulate")
    parser.add_argument("--director", type=str, default=DEFAULT_DIRECTOR_URL, help="Director URL")
    parser.add_argument("--repo", type=str, default=DEFAULT_IMAGE_REPO_URL, help="Image Repo URL")
    parser.add_argument("--duration", type=int, default=None, help="Duration in seconds to run (for testing)")
    args = parser.parse_args()

    logger.info(f"Starting Fleet Simulation with {args.count} vehicles...")
    
    # 1. Bootstrap Trust
    try:
        director_key_hex = await fetch_director_key(args.director)
        logger.info(f"Obtained Director Public Key: {director_key_hex[:16]}...")
    except Exception:
        sys.exit(1)

    # 2. Spawn Agents
    tasks: List[asyncio.Task] = []
    agents: List[VehicleAgent] = []
    
    for i in range(args.count):
        vid = f"sim-v-{uuid.uuid4().hex[:8]}"
        agent = VehicleAgent(
            vehicle_id=vid,
            director_url=args.director,
            image_repo_url=args.repo,
            director_public_key_hex=director_key_hex,
            config={
                "check_interval_sec": 5, 
                "network_latency_ms": 100
            }
        )
        agents.append(agent)
        tasks.append(asyncio.create_task(agent.run_lifecycle()))
        
        # Stagger start times to avoid thundering herd on registration
        await asyncio.sleep(0.05)
        
    logger.info(f"Spawned {len(agents)} vehicle agents.")
    
    # 3. Monitor Loop
    try:
        start_time = time.time()
        while True:
            if args.duration and (time.time() - start_time > args.duration):
                break
                
            # Simple dashboard metrics
            states = [a.state for a in agents]
            
            idle = states.count("IDLE")
            checking = states.count("CHECKING_UPDATES")
            registering = states.count("REGISTERING")
            registered = states.count("REGISTERED")
            error = states.count("ERROR") + states.count("CRASHED") + states.count("UPDATE_FAILED")
            
            # Clear line and print status
            status_msg = (
                f"\r[Fleet Status] Active: {len(agents)} | "
                f"Reg/Init: {registering+registered} | "
                f"Idle: {idle} | "
                f"Checking: {checking} | "
                f"Errors: {error}"
            )
            sys.stdout.write(status_msg)
            sys.stdout.flush()
            
            await asyncio.sleep(0.5)
            
    except KeyboardInterrupt:
        sys.stdout.write("\nStopping simulation...\n")
        # Cancel all tasks
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
