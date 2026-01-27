"""
SecureEV-OTA: Simulation Tests

Tests for the VehicleAgent and FleetManager logic.
Mocks the network layer.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from src.simulation.agent import VehicleAgent
from src.simulation.manager import FleetManager

@pytest.fixture
def mock_ecu():
    with patch("src.simulation.agent.PrimaryECU") as MockECU:
        yield MockECU

@pytest.mark.asyncio
async def test_agent_lifecycle(mock_ecu):
    """Test that agent registers and polls."""
    
    # Setup Mock ECU instance
    instance = mock_ecu.return_value
    instance.register = AsyncMock()
    instance.poll_for_updates = AsyncMock()
    
    # Callback to track status
    statuses = []
    def callback(vid, status):
        statuses.append(status)
        
    agent = VehicleAgent(
        director_url="http://d",
        image_repo_url="http://i",
        director_pub_key="KEY",
        status_callback=callback
    )
    
    # Run agent in background task
    task = asyncio.create_task(agent.run())
    
    # Let it run for a bit (it sleeps 0.1-2.0s for registration, then 1-5s for polling)
    # We'll use asyncio.sleep(0) to yield execution but since we mock sleep, it's tricky.
    # Instead, we rely on the fact that random.uniform is called.
    
    # To test quickly, we patch random.uniform to return tiny delay
    with patch("random.uniform", return_value=0.01):
        # Allow cycle to run (real sleep yields to agent task)
        await asyncio.sleep(0.1)
        
        # Stop it
        agent.stop()
        await task
            
    # Verification
    instance.register.assert_called()
    instance.poll_for_updates.assert_called()
    
    assert "STARTING" in statuses
    assert "REGISTERED" in statuses
    assert "POLLING" in statuses


@pytest.mark.asyncio
async def test_fleet_manager():
    """Test manager spawning and aggregation."""
    
    manager = FleetManager("d", "i", "k")
    
    # Spawn 5 agents
    # We mock VehicleAgent to avoid real logic
    with patch("src.simulation.manager.VehicleAgent") as MockAgent:
        manager.spawn_agents(5)
        assert len(manager.agents) == 5
        
        # Simulate callbacks
        manager._update_status("v1", "IDLE")
        manager._update_status("v2", "IDLE")
        manager._update_status("v3", "ERROR")
        
        stats = manager.get_stats()
        assert stats["IDLE"] == 2
        assert stats["ERROR"] == 1
        
        # Start/Stop
        MockAgent.return_value.run = AsyncMock()
        await manager.start_simulation()
        assert len(manager.agent_tasks) == 5
        
        await manager.stop_simulation()
        # Should call stop on agents
        MockAgent.return_value.stop.assert_called()
