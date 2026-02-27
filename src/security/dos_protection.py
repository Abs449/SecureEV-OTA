"""
SecureEV-OTA: Denial-of-Service (DoS) Protection

This module provides adaptive multi-layer protection against DoS attacks,
addressing vulnerabilities in the original Uptane framework where
drop-request or slow-retrieval attacks could disrupt services.
"""

from __future__ import annotations

import time
import threading
from typing import Dict, Optional, Callable
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """
    Thread-safe Token Bucket algorithm for rate limiting.

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
        self._lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        """
        Consume tokens from the bucket (thread-safe).

        Returns:
            True if tokens were consumed, False if rate limited
        """
        with self._lock:
            self._refill_locked()

            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

    def _refill_locked(self) -> None:
        """Refill tokens based on elapsed time (must be called with lock held)."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.last_update = now

    def refill(self) -> None:
        """Public method to refill tokens based on elapsed time (thread-safe)."""
        with self._lock:
            self._refill_locked()

    def reset_tokens(self) -> None:
        """
        Reset tokens to full capacity (thread-safe).

        Use this to restore a bucket to its maximum capacity,
        e.g., when resetting a vehicle after successful registration.
        """
        with self._lock:
            self.tokens = self.capacity
            self.last_update = time.time()

    def time_until_next_token(self) -> float:
        """
        Calculate time until at least 1 token is available.

        Returns:
            Seconds until next token available, or 0.0 if tokens available now
        """
        with self._lock:
            self._refill_locked()

            if self.tokens >= 1.0:
                return 0.0
            if self.fill_rate <= 0:
                return float('inf')
            return (1.0 - self.tokens) / self.fill_rate

    @property
    def available_tokens(self) -> float:
        """Get current available tokens (thread-safe)."""
        with self._lock:
            self._refill_locked()
            return self.tokens


class DoSProtection:
    """
    Multi-layer DoS protection manager.

    Features:
    - Thread-safe per-vehicle rate limiting
    - Global rate limiting
    - Progressive timeouts with exponential backoff
    - Malicious request filtering and blacklisting
    - Memory management with stale vehicle cleanup
    """

    # Default configuration
    DEFAULT_GLOBAL_CAPACITY = 1000.0
    DEFAULT_GLOBAL_RATE = 100.0  # tokens per second
    DEFAULT_PER_VEHICLE_CAPACITY = 100.0
    DEFAULT_PER_VEHICLE_RATE = 10.0  # tokens per second
    DEFAULT_MAX_VEHICLES = 10000
    DEFAULT_STALE_TIMEOUT = 3600  # 1 hour
    DEFAULT_BLACKLIST_THRESHOLD = 10
    DEFAULT_MAX_VIOLATIONS = 5

    # Exponential backoff configuration
    DEFAULT_BASE_BACKOFF = 1.0  # seconds
    DEFAULT_MAX_BACKOFF = 300.0  # 5 minutes max

    def __init__(
        self,
        global_capacity: float = DEFAULT_GLOBAL_CAPACITY,
        global_rate: float = DEFAULT_GLOBAL_RATE,
        per_vehicle_capacity: float = DEFAULT_PER_VEHICLE_CAPACITY,
        per_vehicle_rate: float = DEFAULT_PER_VEHICLE_RATE,
        max_vehicles: int = DEFAULT_MAX_VEHICLES,
        stale_timeout: float = DEFAULT_STALE_TIMEOUT,
        blacklist_threshold: int = DEFAULT_BLACKLIST_THRESHOLD,
        base_backoff: float = DEFAULT_BASE_BACKOFF,
        max_backoff: float = DEFAULT_MAX_BACKOFF,
    ):
        """
        Initialize DoS protection with configurable parameters.

        Args:
            global_capacity: Maximum tokens in global bucket
            global_rate: Global refill rate (tokens/second)
            per_vehicle_capacity: Max tokens per vehicle bucket
            per_vehicle_rate: Per-vehicle refill rate (tokens/second)
            max_vehicles: Maximum number of vehicles to track
            stale_timeout: Seconds of inactivity before vehicle is stale
            blacklist_threshold: Invalid requests before blacklisting
            base_backoff: Base backoff time in seconds for exponential backoff
            max_backoff: Maximum backoff time in seconds
        """
        self.global_limiter = TokenBucket(global_capacity, global_rate)

        self.pv_capacity = per_vehicle_capacity
        self.pv_rate = per_vehicle_rate
        self.max_vehicles = max_vehicles
        self.stale_timeout = stale_timeout
        self.blacklist_threshold = blacklist_threshold
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff

        # Thread-safe data structures
        self._lock = threading.RLock()
        self._vehicle_limiters: Dict[str, TokenBucket] = {}
        self._vehicle_last_seen: Dict[str, float] = {}
        self._attack_counts: Dict[str, int] = defaultdict(int)
        self._violation_counts: Dict[str, int] = defaultdict(int)
        self._blacklist: set = set()
        self._block_expiry: Dict[str, float] = {}  # For temporary blocks

    def is_request_allowed(self, vehicle_id: str) -> bool:
        """
        Check if a request from a vehicle is allowed (thread-safe).

        Args:
            vehicle_id: Unique identifier for the vehicle

        Returns:
            True if allowed, False if blocked or rate limited
        """
        with self._lock:
            # Check if vehicle is permanently blacklisted
            if vehicle_id in self._blacklist:
                logger.warning(f"Request from blacklisted vehicle: {vehicle_id}")
                return False

            # Check if vehicle is temporarily blocked (exponential backoff)
            if vehicle_id in self._block_expiry:
                if time.time() < self._block_expiry[vehicle_id]:
                    return False
                else:
                    # Block expired, remove it
                    del self._block_expiry[vehicle_id]
                    self._violation_counts[vehicle_id] = 0

            # Check per-vehicle rate limit first (before consuming global token)
            bucket = self._vehicle_limiters.get(vehicle_id)
            if bucket is None:
                # Create new limiter if under max vehicles
                if len(self._vehicle_limiters) >= self.max_vehicles:
                    logger.error(f"Max vehicle limit reached: {self.max_vehicles}")
                    self._cleanup_stale_vehicles()
                    if len(self._vehicle_limiters) >= self.max_vehicles:
                        return False

                bucket = TokenBucket(self.pv_capacity, self.pv_rate)
                self._vehicle_limiters[vehicle_id] = bucket
                self._vehicle_last_seen[vehicle_id] = time.time()

            # Consume vehicle bucket first
            if not bucket.consume():
                # Track violation for exponential backoff
                violation_count = self._violation_counts.get(vehicle_id, 0) + 1
                self._violation_counts[vehicle_id] = violation_count

                # Compute exponential backoff duration
                backoff_seconds = min(
                    self.base_backoff * (2 ** (violation_count - 1)),
                    self.max_backoff
                )
                self._block_expiry[vehicle_id] = time.time() + backoff_seconds
                # Note: We rely solely on _block_expiry for temporary blocks, not _blacklist

                logger.warning(f"Rate limit exceeded for {vehicle_id}, "
                             f"violation #{violation_count}, blocking for {backoff_seconds:.1f}s")
                return False

            # Check global rate limit only after vehicle token is successfully consumed
            if not self.global_limiter.consume():
                logger.warning(f"Global rate limit exceeded")
                return False

            # Update last seen timestamp
            self._vehicle_last_seen[vehicle_id] = time.time()
            return True

    def get_retry_after(self, vehicle_id: str) -> float:
        """
        Calculate seconds until request should be retried.

        Args:
            vehicle_id: Unique identifier for the vehicle

        Returns:
            Seconds to wait before retrying (0.0 if allowed now)
        """
        with self._lock:
            # Check temporary block first (exponential backoff)
            if vehicle_id in self._block_expiry:
                remaining = self._block_expiry[vehicle_id] - time.time()
                if remaining > 0:
                    return max(0.0, remaining)
                # Block expired, clean it up
                del self._block_expiry[vehicle_id]
                # Reset violation count to match is_request_allowed behavior
                if vehicle_id in self._violation_counts:
                    self._violation_counts[vehicle_id] = 0

            # Then check permanent blacklist
            if vehicle_id in self._blacklist:
                return 3600.0  # 1 hour for permanent blacklist

            # Calculate time until global bucket has tokens
            global_wait = self.global_limiter.time_until_next_token()

            # Calculate time until vehicle bucket has tokens
            bucket = self._vehicle_limiters.get(vehicle_id)
            vehicle_wait = bucket.time_until_next_token() if bucket else 0.0

            return max(global_wait, vehicle_wait)

    def report_invalid_request(self, vehicle_id: str) -> None:
        """
        Report an invalid (possibly malicious) request.
        Too many invalid requests will result in blacklisting.

        Args:
            vehicle_id: Unique identifier for the vehicle
        """
        with self._lock:
            self._attack_counts[vehicle_id] += 1

            attack_count = self._attack_counts[vehicle_id]

            # Threshold for blacklisting
            if attack_count >= self.blacklist_threshold:
                self._blacklist.add(vehicle_id)
                logger.warning(f"Vehicle blacklisted: {vehicle_id} (attacks: {attack_count})")

    def reset_vehicle(self, vehicle_id: str) -> None:
        """
        Reset counters and blocks for a vehicle (e.g., on successful registration).

        Args:
            vehicle_id: Unique identifier for the vehicle
        """
        with self._lock:
            # Remove from blacklist
            if vehicle_id in self._blacklist:
                self._blacklist.remove(vehicle_id)

            # Clear temporary block
            if vehicle_id in self._block_expiry:
                del self._block_expiry[vehicle_id]

            # Reset counters
            self._attack_counts[vehicle_id] = 0
            self._violation_counts[vehicle_id] = 0

            # Reset vehicle limiter tokens
            if vehicle_id in self._vehicle_limiters:
                self._vehicle_limiters[vehicle_id].refill()

            # Update last seen
            self._vehicle_last_seen[vehicle_id] = time.time()

    def get_status(self, vehicle_id: str) -> Dict:
        """
        Get status information for a vehicle.

        Args:
            vehicle_id: Unique identifier for the vehicle

        Returns:
            Dict with status information
        """
        with self._lock:
            bucket = self._vehicle_limiters.get(vehicle_id)
            return {
                "blacklisted": vehicle_id in self._blacklist,
                "temporarily_blocked": vehicle_id in self._block_expiry,
                "attack_count": self._attack_counts.get(vehicle_id, 0),
                "violation_count": self._violation_counts.get(vehicle_id, 0),
                "available_tokens": bucket.available_tokens if bucket else 0.0,
                "last_seen": self._vehicle_last_seen.get(vehicle_id),
            }

    def _cleanup_stale_vehicles(self) -> int:
        """
        Remove vehicles that haven't been seen recently.

        Returns:
            Number of vehicles removed
        """
        now = time.time()
        stale_vehicles = [
            vid for vid, last_seen in self._vehicle_last_seen.items()
            if now - last_seen > self.stale_timeout
        ]

        for vid in stale_vehicles:
            self._vehicle_limiters.pop(vid, None)
            self._vehicle_last_seen.pop(vid, None)
            self._attack_counts.pop(vid, None)
            self._violation_counts.pop(vid, None)
            self._block_expiry.pop(vid, None)

        if stale_vehicles:
            logger.info(f"Cleaned up {len(stale_vehicles)} stale vehicles")

        return len(stale_vehicles)

    def get_stats(self) -> Dict:
        """
        Get overall protection statistics.

        Returns:
            Dict with statistics
        """
        with self._lock:
            return {
                "active_vehicles": len(self._vehicle_limiters),
                "blacklisted_count": len(self._blacklist),
                "temporarily_blocked": len(self._block_expiry),
                "global_available_tokens": self.global_limiter.available_tokens,
            }

    def unblacklist(self, vehicle_id: str) -> bool:
        """
        Remove a vehicle from the blacklist.

        Args:
            vehicle_id: Unique identifier for the vehicle

        Returns:
            True if vehicle was blacklisted and is now removed
        """
        with self._lock:
            if vehicle_id in self._blacklist:
                self._blacklist.remove(vehicle_id)
                self.reset_vehicle(vehicle_id)
                return True
            return False
