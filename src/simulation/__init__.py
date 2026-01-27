"""
SecureEV-OTA: Simulation Module

This module simulates a fleet of vehicles connecting to the backend services.
"""

from src.simulation.agent import VehicleAgent
from src.simulation.manager import FleetManager

__all__ = ["VehicleAgent", "FleetManager"]
