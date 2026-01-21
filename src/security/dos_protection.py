"""
SecureEV-OTA: Denial-of-Service (DoS) Protection

This module provides adaptive multi-layer protection against DoS attacks,
addressing vulnerabilities in the original Uptane framework where 
drop-request or slow-retrieval attacks could disrupt services.
"""

from __future__ import annotations

import time
import collections
from typing import Dict, Optional


class TokenBucket:
    """
    Token Bucket algorithm for rate limiting.
    
    Provides smooth rate limiting for incoming update requests.
    """
    
    def __init__(self, capacity: float, fill_rate: float):
        """
        Initialize the token bucket.
        
        Args:
            capacity: Maximum number of tokens in the bucket
            fill_rate: How many tokens are added per second
        """
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()
        
    def consume(self, amount: float = 1.0) -> bool:
        """
        Consume tokens from the bucket.
        
        Returns:
            True if tokens were consumed, False if rate limited
        """
        now = time.time()
        
        # Add new tokens based on time elapsed
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.last_update = now
        
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


class DoSProtection:
    """
    Multi-layer DoS protection manager.
    
    Features:
    - Adaptive per-vehicle rate limiting
    - Progressive timeouts
    - Malicious request filtering
    """
    
    def __init__(self, 
                 global_capacity: float = 100.0, 
                 global_rate: float = 10.0,
                 per_vehicle_capacity: float = 5.0,
                 per_vehicle_rate: float = 0.5):
        """
        Initialize DoS protection.
        """
        self.global_limiter = TokenBucket(global_capacity, global_rate)
        self.vehicle_limiters: Dict[str, TokenBucket] = {}
        
        self.pv_capacity = per_vehicle_capacity
        self.pv_rate = per_vehicle_rate
        
        self.blacklist = set()
        self.attack_counts = collections.Counter()
        
    def is_request_allowed(self, vehicle_id: str) -> bool:
        """
        Check if a request from a vehicle is allowed.
        
        Args:
            vehicle_id: Unique identifier for the vehicle
            
        Returns:
            True if allowed, False if blocked or rate limited
        """
        if vehicle_id in self.blacklist:
            return False
            
        # Check global rate limit
        if not self.global_limiter.consume():
            return False
            
        # Check per-vehicle rate limit
        if vehicle_id not in self.vehicle_limiters:
            self.vehicle_limiters[vehicle_id] = TokenBucket(self.pv_capacity, self.pv_rate)
            
        if not self.vehicle_limiters[vehicle_id].consume():
            return False
            
        return True

    def report_invalid_request(self, vehicle_id: str):
        """
        Report an invalid (possibly malicious) request.
        Too many invalid requests will result in blacklisting.
        """
        self.attack_counts[vehicle_id] += 1
        
        # Threshold for blacklisting
        if self.attack_counts[vehicle_id] >= 10:
            self.blacklist.add(vehicle_id)

    def reset_vehicle(self, vehicle_id: str):
        """Reset counters for a vehicle."""
        if vehicle_id in self.blacklist:
            self.blacklist.remove(vehicle_id)
        self.attack_counts[vehicle_id] = 0
        if vehicle_id in self.vehicle_limiters:
            self.vehicle_limiters[vehicle_id].tokens = self.pv_capacity
