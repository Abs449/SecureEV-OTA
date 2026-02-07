"""
SecureEV-OTA: Server Package

Contains the backend services for the OTA framework:
- Director Repository: Vehicle management and manifest generation
- Image Repository: Firmware storage and encrypted delivery
"""

from src.server.director import app as director_app
from src.server.image_repo import app as image_repo_app
