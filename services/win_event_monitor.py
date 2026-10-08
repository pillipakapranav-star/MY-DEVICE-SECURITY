"""
Aegis Sentinel - Windows Security Event Log Monitor
Audits Windows Event Log for Event ID 4625 (Logon Failure).
When 3 consecutive failed logon attempts occur on Windows lock screen,
triggers the Case 1 breach protocol.
"""

import time
import threading
import subprocess
from typing import Optional, Callable
from services.security_monitor import SecurityMonitor


class WindowsEventMonitor:
    """Monitors Windows Security Event Log (Event ID 4625) in background."""

    def __init__(self, security_monitor: SecurityMonitor):
        self.security_monitor = security_monitor
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_event_time = None

    def start_monitoring(self):
        """Start background polling of Windows Security Event Log."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[WinEventMonitor] Background Windows Security Event auditor started.")

    def stop_monitoring(self):
        """Stop background auditing."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        print("[WinEventMonitor] Background Windows Security Event auditor stopped.")

    def _monitor_loop(self):
        """Poll for new Event 4625 records."""
        ps_cmd = (
            'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 1 '
            '-ErrorAction SilentlyContinue | Select-Object -ExpandProperty TimeCreated'
        )

        while self._running:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = result.stdout.strip()
                if output:
                    if self._last_event_time is None:
                        # First read: memorize current latest event
                        self._last_event_time = output
                    elif output != self._last_event_time:
                        # New failed logon event detected!
                        self._last_event_time = output
                        print(f"[WinEventMonitor] [ALERT] Windows Logon Failure Event ID 4625 detected at {output}!")
                        self.security_monitor.record_password_attempt(is_correct=False)
            except Exception:
                pass

            time.sleep(2.0)
