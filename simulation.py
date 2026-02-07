"""
SecureEV-OTA: Fleet Simulation Demo

This script runs the massive fleet simulation with robust error handling.
Prerequisites:
- Director Service running on port 8000
- Image Repo running on port 8001
"""

import asyncio
import httpx
import sys
import signal
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from rich import box

import os
from src.simulation.manager import FleetManager

import logging

DIRECTOR_URL = os.getenv("DIRECTOR_URL", "http://localhost:8000")
REPO_URL = os.getenv("IMAGE_REPO_URL", "http://localhost:8001")
VEHICLE_COUNT = int(os.getenv("VEHICLE_COUNT", "50"))

# Configure detailed logging for verification
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("simulation_detailed.log", mode="w")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", "%H:%M:%S")
file_handler.setFormatter(formatter)
root_logger.addHandler(file_handler)

console = Console()
shutdown_event = asyncio.Event()

async def check_services():
    """Verify backend services are running."""
    services_ok = True
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        # Check Director
        try:
            resp = await client.get(f"{DIRECTOR_URL}/")
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "online":
                console.print(f"✅ Director: [green]Online[/green]")
            else:
                console.print(f"❌ Director: [red]Unexpected response[/red]")
                services_ok = False
        except Exception as e:
            console.print(f"❌ Director: [red]Not reachable[/red] - {e}")
            services_ok = False
        
        # Check Image Repo
        try:
            resp = await client.get(f"{REPO_URL}/")
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "online":
                console.print(f"✅ Image Repo: [green]Online[/green]")
            else:
                console.print(f"❌ Image Repo: [red]Unexpected response[/red]")
                services_ok = False
        except Exception as e:
            console.print(f"❌ Image Repo: [red]Not reachable[/red] - {e}")
            services_ok = False
    
    return services_ok

async def fetch_director_key():
    """Bootstrap trust by fetching the key from Director root endpoint."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{DIRECTOR_URL}/")
            resp.raise_for_status()
            data = resp.json()
            return data.get("public_key", "")
    except httpx.ConnectError:
        console.print("[bold red]Error:[/bold red] Cannot connect to Director.")
        console.print("Please run: [cyan]./start_servers.ps1[/cyan]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error connecting to Director:[/bold red] {e}")
        sys.exit(1)

async def upload_test_firmware():
    """Upload test firmware to Image Repository."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            firmware_data = b"SECUREEV-OTA FIRMWARE v2.1.0 " + b"\x00" * 1000
            resp = await client.post(
                f"{REPO_URL}/upload?filename=firmware-v210.bin",
                content=firmware_data
            )
            if resp.status_code == 200:
                console.print("✅ Test firmware uploaded")
            else:
                console.print(f"⚠️  Firmware upload: {resp.text}")
    except Exception as e:
        console.print(f"⚠️  Could not upload firmware: {e}")

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
        "IDLE": "green",
        "Updated": "green",
        "ERROR": "red",
        "CRASH": "bold red",
        "STOPPED": "dim"
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
        
        # Truncate long status messages
        display_status = status[:30] + "..." if len(status) > 30 else status
        table.add_row(f"[{color}]{display_status}[/]", str(count), f"[{color}]{bar}[/]")

    layout["body"].update(Panel(table, title="Fleet Status"))
    
    return layout

async def main():
    console.print("[bold cyan]╔══════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║   SecureEV-OTA Fleet Simulation      ║[/bold cyan]")
    console.print("[bold cyan]╚══════════════════════════════════════╝[/bold cyan]")
    console.print()
    
    # 1. Pre-flight checks
    console.print("[bold]Pre-flight Checks:[/bold]")
    if not await check_services():
        console.print("\n[red]Please start the backend services first:[/red]")
        console.print("  Director: uvicorn src.server.director:app --port 8000")
        console.print("  Image Repo: uvicorn src.server.image_repo:app --port 8001")
        sys.exit(1)
    
    # 2. Upload test firmware
    await upload_test_firmware()
    
    # 3. Get Director key
    pub_key = await fetch_director_key()
    if not pub_key:
        console.print("[red]Could not get Director public key[/red]")
        sys.exit(1)
    console.print(f"✅ Director Key: [dim]{pub_key[:20]}...[/dim]")
    
    # 4. Init Manager
    console.print(f"\n[bold]Spawning {VEHICLE_COUNT} vehicles...[/bold]")
    manager = FleetManager(DIRECTOR_URL, REPO_URL, pub_key)
    manager.spawn_agents(VEHICLE_COUNT)
    
    # 5. Run Loop with error handling
    console.print("[green]Starting simulation (Press Ctrl+C to stop)[/green]\n")
    
    try:
        await manager.start_simulation()
        
        with Live(generate_dashboard(manager), refresh_per_second=2, console=console) as live:
            while not shutdown_event.is_set():
                try:
                    live.update(generate_dashboard(manager))
                    await asyncio.sleep(0.5)
                except Exception as e:
                    # Dashboard error shouldn't stop simulation
                    pass
                    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"\n[red]Simulation error:[/red] {e}")
    finally:
        console.print("\n[yellow]Stopping simulation...[/yellow]")
        try:
            await manager.stop_simulation()
        except Exception:
            pass
        console.print("[green]Simulation stopped.[/green]")
        
        # Print final stats
        stats = manager.get_stats()
        console.print("\n[bold]Final Statistics:[/bold]")
        for status, count in sorted(stats.items()):
            console.print(f"  {status}: {count}")

def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    shutdown_event.set()

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
    except Exception as e:
        console.print(f"\n[red]Fatal error:[/red] {e}")
        sys.exit(1)
