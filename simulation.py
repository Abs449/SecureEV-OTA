"""
SecureEV-OTA: Fleet Simulation Demo

This script runs the massive fleet simulation.
Prerequisites:
- Director Service running on port 8000
- Image Repo running on port 8001
"""

import asyncio
import httpx
import sys
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from rich import box

from src.simulation.manager import FleetManager

DIRECTOR_URL = "http://localhost:8000"
REPO_URL = "http://localhost:8001"
VEHICLE_COUNT = 50

console = Console()

async def fetch_director_key():
    """Bootstrap trust by fetching the ephemeral key from Director."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{DIRECTOR_URL}/public_key")
            resp.raise_for_status()
            return resp.json()["public_key"]
    except Exception as e:
        console.print(f"[bold red]Error connecting to Director:[/bold red] {e}")
        console.print("Make sure the backend services are running!")
        sys.exit(1)

def generate_dashboard(manager: FleetManager) -> Layout:
    """Create the rich UI layout."""
    stats = manager.get_stats()
    total = manager.get_active_count()
    
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    
    # Header
    layout["header"].update(
        Panel(f"SecureEV-OTA Fleet Simulation | Active Vehicles: {total}", 
              style="bold white on blue")
    )
    
    # Stats Table
    table = Table(box=box.SIMPLE)
    table.add_column("Status", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Bar_Chart", justify="left")
    
    colors = {
        "STARTING": "yellow",
        "REGISTERED": "blue",
        "POLLING": "magenta",
        "IDLE (Updated)": "green",
        "ERROR": "red",
        "CRASH": "bold red"
    }

    for status, count in sorted(stats.items()):
        color = "white"
        for key, c in colors.items():
            if key in status:
                color = c
                break
        
        # Simple bar chart
        bar_len = int((count / max(total, 1)) * 40)
        bar = "█" * bar_len
        
        table.add_row(f"[{color}]{status}[/]", str(count), f"[{color}]{bar}[/]")

    layout["body"].update(Panel(table, title="Fleet Status"))
    
    return layout

async def main():
    console.print("[bold green]Starting SecureEV-OTA Simulation...[/bold green]")
    
    # 1. Bootstrap
    pub_key = await fetch_director_key()
    console.print(f"Received Director Public Key: [cyan]{pub_key[:16]}...[/cyan]")
    
    # 2. Init Manager
    manager = FleetManager(DIRECTOR_URL, REPO_URL, pub_key)
    
    # 3. Spawn Fleet
    console.print(f"Spawning {VEHICLE_COUNT} vehicles...")
    manager.spawn_agents(VEHICLE_COUNT)
    
    # 4. Run Loop
    await manager.start_simulation()
    
    try:
        with Live(generate_dashboard(manager), refresh_per_second=4) as live:
            while True:
                live.update(generate_dashboard(manager))
                await asyncio.sleep(0.25)
    except KeyboardInterrupt:
        console.print("Stopping simulation...")
        await manager.stop_simulation()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
