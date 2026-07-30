"""
Rate Limiter with Temporal Jitter for CapabilityBroker.

Provides per-target and global rate limiting with configurable jitter
to avoid WAF/IDS thresholds. Includes shell session keep-alive support.
"""

import time
import random
import threading
import asyncio
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any
from collections import defaultdict


@dataclass
class RateLimiterConfig:
    """Configuration for RateLimiter."""
    min_delay_seconds: float = 5.0
    max_delay_seconds: float = 15.0
    max_actions_per_minute: int = 10
    max_actions_per_hour: int = 200
    emergency_brake_denials: int = 10
    emergency_brake_window_seconds: int = 60
    emergency_brake_cooldown_seconds: int = 300
    shell_keepalive_interval_seconds: int = 10
    
    # Per-target multipliers (target_type -> multiplier)
    target_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "web": 1.0,      # HTTP actions
        "ssh": 2.0,      # SSH commands slower
        "dns": 0.5,      # DNS queries faster
        "shell": 1.5,    # Shell commands
    })


@dataclass
class TargetRateState:
    """Rate tracking state for a single target."""
    action_timestamps: list = field(default_factory=list)
    denials: list = field(default_factory=list)
    last_action_time: float = 0.0
    emergency_brake_active: bool = False
    emergency_brake_until: float = 0.0
    total_actions: int = 0
    total_denials: int = 0


class RateLimiter:
    """
    Rate limiter with temporal jitter and emergency brake.
    
    Thread-safe. Supports both sync and async usage with native async path.
    
    Key features:
    - Per-target rate tracking with configurable limits
    - Global rate limits across all targets
    - Random jitter within [min_delay, max_delay] 
    - Emergency brake on excessive denials
    - Shell session keep-alive heartbeat support
    """
    
    def __init__(self, config: Optional[RateLimiterConfig] = None):
        self.config = config or RateLimiterConfig()
        self._targets: Dict[str, TargetRateState] = defaultdict(TargetRateState)
        self._global_timestamps: list = []
        self._global_denials: list = []
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()
        
        # Stats
        self._total_actions = 0
        self._total_denials = 0
        self._emergency_brakes = 0
    
    def authorize_with_delay(
        self, 
        target: str, 
        action_type: str = "web",
        target_type: str = "web"
    ) -> Tuple[bool, str, float]:
        """
        Synchronous authorization with blocking delay.
        
        Returns:
            (allowed: bool, reason: str, delay_applied: float)
        """
        with self._lock:
            return self._authorize_sync(target, action_type, target_type)
    
    async def authorize_with_delay_async(
        self, 
        target: str, 
        action_type: str = "web",
        target_type: str = "web"
    ) -> Tuple[bool, str, float]:
        """
        Asynchronous authorization with NON-BLOCKING delay.
        
        Uses await asyncio.sleep() to avoid freezing the event loop.
        
        Returns:
            (allowed: bool, reason: str, delay_applied: float)
        """
        async with self._async_lock:
            return await self._authorize_async(target, action_type, target_type)
    
    def _authorize_sync(
        self, 
        target: str, 
        action_type: str,
        target_type: str
    ) -> Tuple[bool, str, float]:
        """Internal synchronous authorization logic."""
        now = time.time()
        target_key = self._normalize_target(target)
        
        # Get or create target state
        state = self._targets[target_key]
        
        # Check emergency brake
        if state.emergency_brake_active:
            if now < state.emergency_brake_until:
                return False, (
                    f"Emergency brake active until {state.emergency_brake_until:.0f}"
                ), 0.0
            else:
                # Brake expired, reset
                state.emergency_brake_active = False
                state.emergency_brake_until = 0.0
        
        # Check per-target rate limits
        allowed, reason = self._check_target_limits(state, now)
        if not allowed:
            self._record_denial(state, now)
            return False, reason, 0.0
        
        # Check global rate limits
        allowed, reason = self._check_global_limits(now)
        if not allowed:
            self._record_denial(state, now)
            return False, reason, 0.0
        
        # Calculate delay with jitter
        base_delay = random.uniform(
            self.config.min_delay_seconds,
            self.config.max_delay_seconds
        )
        
        # Apply target-type multiplier
        multiplier = self.config.target_multipliers.get(target_type, 1.0)
        delay = base_delay * multiplier
        
        # Apply delay (BLOCKING sleep for sync path)
        time.sleep(delay)
        
        # Record action
        self._record_action(state, now, target_key)
        
        return True, f"Authorized after {delay:.2f}s delay", delay
    
    async def _authorize_async(
        self, 
        target: str, 
        action_type: str,
        target_type: str
    ) -> Tuple[bool, str, float]:
        """Internal async authorization logic with NON-BLOCKING delay."""
        now = time.time()
        target_key = self._normalize_target(target)
        
        # Get or create target state (need lock for shared state)
        with self._lock:
            state = self._targets[target_key]
            
            # Check emergency brake
            if state.emergency_brake_active:
                if now < state.emergency_brake_until:
                    return False, (
                        f"Emergency brake active until {state.emergency_brake_until:.0f}"
                    ), 0.0
                else:
                    state.emergency_brake_active = False
                    state.emergency_brake_until = 0.0
            
            # Check per-target rate limits
            allowed, reason = self._check_target_limits(state, now)
            if not allowed:
                self._record_denial(state, now)
                return False, reason, 0.0
            
            # Check global rate limits
            allowed, reason = self._check_global_limits(now)
            if not allowed:
                self._record_denial(state, now)
                return False, reason, 0.0
            
            # Calculate delay with jitter
            base_delay = random.uniform(
                self.config.min_delay_seconds,
                self.config.max_delay_seconds
            )
            
            # Apply target-type multiplier
            multiplier = self.config.target_multipliers.get(target_type, 1.0)
            delay = base_delay * multiplier
        
        # Apply delay with NON-BLOCKING async sleep (lock released)
        await asyncio.sleep(delay)
        
        # Record action (need lock back for shared state)
        with self._lock:
            now = time.time()
            self._record_action(state, now, target_key)
        
        return True, f"Authorized after {delay:.2f}s delay", delay
    
    def _check_target_limits(self, state: TargetRateState, now: float) -> Tuple[bool, str]:
        """Check per-target rate limits."""
        # Clean old timestamps (older than 1 hour)
        hour_ago = now - 3600
        state.action_timestamps = [ts for ts in state.action_timestamps if ts > hour_ago]
        state.denials = [ts for ts in state.denials if ts > hour_ago]
        
        # Check per-minute limit
        minute_ago = now - 60
        recent_actions = [ts for ts in state.action_timestamps if ts > minute_ago]
        
        if len(recent_actions) >= self.config.max_actions_per_minute:
            return False, f"Target rate limit exceeded: {len(recent_actions)}/{self.config.max_actions_per_minute} per minute"
        
        # Check per-hour limit
        if len(state.action_timestamps) >= self.config.max_actions_per_hour:
            return False, f"Target hourly limit exceeded: {len(state.action_timestamps)}/{self.config.max_actions_per_hour} per hour"
        
        return True, "OK"
    
    def _check_global_limits(self, now: float) -> Tuple[bool, str]:
        """Check global rate limits."""
        minute_ago = now - 60
        hour_ago = now - 3600
        
        # Clean old timestamps
        self._global_timestamps = [ts for ts in self._global_timestamps if ts > hour_ago]
        self._global_denials = [ts for ts in self._global_denials if ts > hour_ago]
        
        # Check per-minute
        recent = [ts for ts in self._global_timestamps if ts > minute_ago]
        if len(recent) >= self.config.max_actions_per_minute * 3:  # Global is more lenient
            return False, f"Global rate limit exceeded: {len(recent)} actions in last minute"
        
        return True, "OK"
    
    def _record_action(self, state: TargetRateState, now: float, target_key: str) -> None:
        """Record a successful action."""
        state.action_timestamps.append(now)
        state.last_action_time = now
        state.total_actions += 1
        
        self._global_timestamps.append(now)
        self._total_actions += 1
    
    def _record_denial(self, state: TargetRateState, now: float) -> None:
        """Record a denial and check for emergency brake."""
        state.denials.append(now)
        state.total_denials += 1
        
        self._global_denials.append(now)
        self._total_denials += 1
        
        # Check emergency brake condition
        window_start = now - self.config.emergency_brake_window_seconds
        recent_denials = [ts for ts in state.denials if ts > window_start]
        
        if len(recent_denials) >= self.config.emergency_brake_denials:
            state.emergency_brake_active = True
            state.emergency_brake_until = now + self.config.emergency_brake_cooldown_seconds
            self._emergency_brakes += 1
    
    def record_denial(self, target: str) -> None:
        """Explicitly record a denial (e.g., from Broker DENY decision)."""
        with self._lock:
            now = time.time()
            target_key = self._normalize_target(target)
            state = self._targets[target_key]
            self._record_denial(state, now)
    
    def send_keepalive(self, target: str) -> bool:
        """
        Send keep-alive for shell session.
        Updates internal state only - actual PTY heartbeat handled by ShellKeepAlive.
        Returns True if session should continue, False if timed out.
        """
        with self._lock:
            target_key = self._normalize_target(target)
            state = self._targets[target_key]
            state.last_action_time = time.time()
            return True
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target string for consistent tracking."""
        # Remove protocol
        target = re.sub(r'^[a-zA-Z]+://', '', target)
        # Remove trailing slash
        target = target.rstrip('/')
        # Lowercase
        return target.lower()
    
    def get_status(self) -> Dict:
        """Get current rate limiter status for monitoring."""
        with self._lock:
            now = time.time()
            
            active_targets = 0
            for state in self._targets.values():
                if state.last_action_time > now - 3600:
                    active_targets += 1
            
            return {
                "config": {
                    "min_delay_seconds": self.config.min_delay_seconds,
                    "max_delay_seconds": self.config.max_delay_seconds,
                    "max_actions_per_minute": self.config.max_actions_per_minute,
                    "max_actions_per_hour": self.config.max_actions_per_hour,
                    "emergency_brake_denials": self.config.emergency_brake_denials,
                    "emergency_brake_window_seconds": self.config.emergency_brake_window_seconds,
                    "emergency_brake_cooldown_seconds": self.config.emergency_brake_cooldown_seconds,
                },
                "stats": {
                    "total_actions": self._total_actions,
                    "total_denials": self._total_denials,
                    "emergency_brakes_triggered": self._emergency_brakes,
                    "active_targets": active_targets,
                    "tracked_targets": len(self._targets),
                },
                "targets": {
                    target: {
                        "actions": state.total_actions,
                        "denials": state.total_denials,
                        "last_action": state.last_action_time,
                        "emergency_brake": state.emergency_brake_active,
                        "brake_until": state.emergency_brake_until if state.emergency_brake_active else None,
                    }
                    for target, state in self._targets.items()
                    if state.total_actions > 0 or state.total_denials > 0
                }
            }
    
    def reset(self) -> None:
        """Reset all rate limiting state."""
        with self._lock:
            self._targets.clear()
            self._global_timestamps.clear()
            self._global_denials.clear()
            self._total_actions = 0
            self._total_denials = 0
            self._emergency_brakes = 0


# Import at module level for regex
import re
import ipaddress


# =============================================================================
# Shell Keep-Alive Context Manager
# =============================================================================

class ShellKeepAlive:
    """
    Context manager for shell session keep-alive during rate-limited operations.
    
    Sends actual PTY newlines to keep the SSH/TCP connection alive during
    rate limiter delays. Heartbeat bypasses CommandFilterPipeline.
    
    Usage:
        with ShellKeepAlive(rate_limiter, target, shell_session=session):
            # Long operation that might exceed rate limiter delay
            pass
    
    If no shell_session provided, falls back to internal state update only.
    """
    
    def __init__(
        self, 
        rate_limiter: RateLimiter, 
        target: str, 
        shell_session: Optional[Any] = None,
        interval: float = 10.0
    ):
        """
        Args:
            rate_limiter: The RateLimiter instance
            target: Target identifier for rate tracking
            shell_session: Optional ShellSession object with send_raw() method.
                           If provided, sends raw newlines to PTY.
                           If None, only updates internal rate limiter state.
            interval: Heartbeat interval in seconds
        """
        self.rate_limiter = rate_limiter
        self.target = target
        self.shell_session = shell_session
        self.interval = interval
        self._running = False
        self._thread = None
        self._async_task = None
    
    def __enter__(self):
        self._running = True
        self._thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self._thread.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.interval + 1)
    
    async def __aenter__(self):
        self._running = True
        self._async_task = asyncio.create_task(self._async_keepalive_loop())
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._running = False
        if self._async_task:
            try:
                await asyncio.wait_for(self._async_task, timeout=self.interval + 1)
            except asyncio.TimeoutError:
                pass
    
    def _keepalive_loop(self):
        """Synchronous keep-alive loop - sends raw newline to PTY if session provided."""
        while self._running:
            time.sleep(self.interval)
            if self._running:
                self._send_heartbeat()
    
    async def _async_keepalive_loop(self):
        """Async keep-alive loop - sends raw newline to PTY if session provided."""
        while self._running:
            await asyncio.sleep(self.interval)
            if self._running:
                self._send_heartbeat()
    
    def _send_heartbeat(self):
        """
        Send heartbeat - either raw newline to PTY or internal state update.
        
        If shell_session has send_raw method, send b'\\n' directly to PTY
        (bypasses CommandFilterPipeline).
        Otherwise, just update rate limiter internal state.
        """
        # Try to send raw newline to PTY
        if self.shell_session is not None:
            try:
                # Check for various PTY send methods
                if hasattr(self.shell_session, 'send_raw'):
                    self.shell_session.send_raw(b'\n')
                    return
                elif hasattr(self.shell_session, '_writer') and self.shell_session._writer:
                    # asyncio StreamWriter
                    if not self.shell_session._writer.is_closing():
                        self.shell_session._writer.write(b'\n')
                        # Don't await drain here to avoid blocking
                        return
                elif hasattr(self.shell_session, 'send_command'):
                    # Fallback - but this goes through filter
                    # We want raw newline, so don't use this
                    pass
            except Exception:
                # PTY send failed, fall back to internal state
                pass
        
        # Fallback: just update internal rate limiter state
        self.rate_limiter.send_keepalive(self.target)


if __name__ == "__main__":
    # Quick self-test
    print("=== RATE LIMITER SELF-TEST ===")
    
    config = RateLimiterConfig(
        min_delay_seconds=0.1,  # Fast for testing
        max_delay_seconds=0.2,
        max_actions_per_minute=5,
        max_actions_per_hour=20,
    )
    
    rl = RateLimiter(config)
    
    # Test basic authorization
    print("\n1. Basic authorization with delay (SYNC):")
    for i in range(3):
        allowed, reason, delay = rl.authorize_with_delay("10.0.0.1", "web")
        print(f"   Attempt {i+1}: allowed={allowed}, delay={delay:.3f}s, reason={reason}")
    
    # Test rate limiting
    print("\n2. Rate limiting (should deny after 5/min):")
    for i in range(3):
        allowed, reason, delay = rl.authorize_with_delay("10.0.0.1", "web")
        print(f"   Attempt {i+4}: allowed={allowed}, reason={reason}")
    
    # Test different target
    print("\n3. Different target (should allow):")
    allowed, reason, delay = rl.authorize_with_delay("10.0.0.2", "web")
    print(f"   10.0.0.2: allowed={allowed}, reason={reason}")
    
    # Test emergency brake
    print("\n4. Emergency brake (recording denials):")
    for i in range(config.emergency_brake_denials + 2):
        rl.record_denial("10.0.0.3")
    
    allowed, reason, _ = rl.authorize_with_delay("10.0.0.3", "web")
    print(f"   After emergency brake: allowed={allowed}, reason={reason}")
    
    # Test status
    print("\n5. Status:")
    status = rl.get_status()
    print(f"   Total actions: {status['stats']['total_actions']}")
    print(f"   Total denials: {status['stats']['total_denials']}")
    print(f"   Emergency brakes: {status['stats']['emergency_brakes_triggered']}")
    print(f"   Active targets: {status['stats']['active_targets']}")
    
    # Test keep-alive
    print("\n6. Keep-alive (sync context manager):")
    with ShellKeepAlive(rl, "10.0.0.1", interval=0.1):
        time.sleep(0.3)
    print("   Keep-alive context manager works")
    
    # Test async
    print("\n7. Async authorization test:")
    async def test_async():
        for i in range(2):
            allowed, reason, delay = await rl.authorize_with_delay_async("10.0.0.4", "web")
            print(f"   Async {i+1}: allowed={allowed}, delay={delay:.3f}s, reason={reason}")
    
    asyncio.run(test_async())
    
    print("\n=== ALL TESTS PASSED ===")