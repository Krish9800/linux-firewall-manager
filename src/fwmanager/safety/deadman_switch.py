"""Safety engine implementing an atomic rollback timer (Deadman's Switch)."""

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from fwmanager.config.settings import settings
from fwmanager.models.rules import FirewallPolicy


@dataclass
class SafetyStatus:
    """Status report of the deadman's switch safety timer."""

    is_armed: bool
    timeout_seconds: float
    elapsed_seconds: float
    remaining_seconds: float
    target_policy_name: str
    reverted: bool = False


class DeadmanSwitch:
    """Guards firewall state transitions with automatic rollback upon unconfirmed application."""

    def __init__(self, default_timeout: Optional[float | int] = None) -> None:
        self.default_timeout: float = float(
            default_timeout if default_timeout is not None else settings.auto_rollback_timeout
        )
        self._lock = threading.Lock()
        self._is_armed = False
        self._start_time: float = 0.0
        self._timeout: float = self.default_timeout
        self._previous_snapshot: Optional[FirewallPolicy] = None
        self._pending_policy: Optional[FirewallPolicy] = None
        self._revert_callback: Optional[Callable[[FirewallPolicy], None]] = None
        self._timer_thread: Optional[threading.Thread] = None
        self._reverted = False

    @property
    def is_armed(self) -> bool:
        """Check if rollback timer is currently running."""
        with self._lock:
            return self._is_armed

    def arm(
        self,
        current_policy: FirewallPolicy,
        pending_policy: FirewallPolicy,
        revert_callback: Callable[[FirewallPolicy], None],
        timeout: Optional[float | int] = None,
    ) -> None:
        """Arm the safety deadman switch with a snapshot and rollback callback."""
        with self._lock:
            if self._is_armed:
                raise RuntimeError("Deadman switch is already armed with a pending transaction.")

            self._timeout = float(timeout if timeout is not None else self.default_timeout)
            self._previous_snapshot = current_policy.model_copy(deep=True)
            self._pending_policy = pending_policy.model_copy(deep=True)
            self._revert_callback = revert_callback
            self._is_armed = True
            self._reverted = False
            self._start_time = time.monotonic()

            self._timer_thread = threading.Thread(target=self._countdown_loop, daemon=True)
            self._timer_thread.start()

    def confirm(self) -> bool:
        """Confirm the new policy; cancels the rollback timer and commits changes."""
        with self._lock:
            if not self._is_armed:
                return False
            self._is_armed = False
            self._previous_snapshot = None
            self._pending_policy = None
            self._revert_callback = None
            return True

    def manual_rollback(self) -> bool:
        """Manually trigger immediate rollback to previous snapshot."""
        with self._lock:
            if not self._is_armed or self._previous_snapshot is None:
                return False
            snapshot = self._previous_snapshot
            callback = self._revert_callback
            self._is_armed = False
            self._reverted = True

        if callback and snapshot:
            callback(snapshot)
        return True

    def _countdown_loop(self) -> None:
        """Background thread monitoring countdown until timeout."""
        time.sleep(self._timeout)
        with self._lock:
            if not self._is_armed or self._previous_snapshot is None:
                return
            snapshot = self._previous_snapshot
            callback = self._revert_callback
            self._is_armed = False
            self._reverted = True

        if callback and snapshot:
            callback(snapshot)

    def get_status(self) -> SafetyStatus:
        """Retrieve live status of the safety switch."""
        with self._lock:
            if not self._is_armed:
                return SafetyStatus(
                    is_armed=False,
                    timeout_seconds=self._timeout,
                    elapsed_seconds=0.0,
                    remaining_seconds=0.0,
                    target_policy_name="",
                    reverted=self._reverted,
                )

            elapsed = time.monotonic() - self._start_time
            remaining = max(0.0, float(self._timeout) - elapsed)
            target_name = self._pending_policy.name if self._pending_policy else "Unknown"

            return SafetyStatus(
                is_armed=True,
                timeout_seconds=self._timeout,
                elapsed_seconds=round(elapsed, 1),
                remaining_seconds=round(remaining, 1),
                target_policy_name=target_name,
                reverted=self._reverted,
            )
