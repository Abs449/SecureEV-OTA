"""
SecureEV-OTA: Fleet Manager (Simulation Orchestrator)

This module orchestrates the simulation. It spawns the requested number of
VehicleAgents and tracks their status.
"""

import asyncio
from typing import Dict, List
from collections import Counter

from src.simulation.agent import VehicleAgent

class FleetManager:
    def __init__(self, 
                 director_url: str, 
                 image_repo_url: str, 
                 director_pub_key: str):
        
        self.director_url = director_url
        self.image_repo_url = image_repo_url
        self.director_pub_key = director_pub_key
        
        self.agents: List[VehicleAgent] = []
        self.agent_tasks: List[asyncio.Task] = []
        
        # Stats: vehicle_id -> status_string
        self.statuses: Dict[str, str] = {}
        
    def spawn_agents(self, count: int):
        """Create N agents."""
        for _ in range(count):
            agent = VehicleAgent(
                self.director_url,
                self.image_repo_url,
                self.director_pub_key,
                status_callback=self._update_status
            )
            self.agents.append(agent)
            
    async def start_simulation(self):
        """Start all agents."""
        for agent in self.agents:
            task = asyncio.create_task(agent.run())
            self.agent_tasks.append(task)
            
    async def stop_simulation(self):
        """Stop all agents."""
        for agent in self.agents:
            agent.stop()
        
        # Wait for cleanup
        if self.agent_tasks:
            await asyncio.gather(*self.agent_tasks, return_exceptions=True)

    def _update_status(self, vehicle_id: str, status: str):
        """Callback from agents."""
        self.statuses[vehicle_id] = status

    def get_stats(self) -> Dict[str, int]:
        """Aggregate stats for dashboard."""
        counts = Counter(self.statuses.values())
        return dict(counts)
        
    def get_active_count(self) -> int:
        return len(self.agents)
