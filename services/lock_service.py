"""
Aegis Sentinel - Lock & Alarm Service
Controls Windows workstation hardware locking (LockWorkStation)
and audible deterrent sirens via Windows winsound.
"""

import sys
import time
import threading
import ctypes


class LockService:
    """Manages workstation locking and audible deterrent sirens."""

    @staticmethod
    def lock_workstation() -> bool:
        """Immediately trigger Windows native hardware lock screen."""
        try:
            if sys.platform == "win32":
                print("[LockService] [LOCK] Invoking Windows LockWorkStation API...")
                res = ctypes.windll.user32.LockWorkStation()
                return bool(res)
            else:
                print("[LockService] Non-Windows OS detected, simulation lock triggered.")
                return True
        except Exception as e:
            print(f"[LockService] [ERROR] Failed to invoke LockWorkStation: {e}")
            return False

    @staticmethod
    def play_siren_async(duration_sec: float = 3.0):
        """Play an attention-grabbing pulsing security alarm siren in background thread."""
        def _siren_worker():
            try:
                import winsound
                end_time = time.time() + duration_sec
                while time.time() < end_time:
                    # High pitch alert warble
                    winsound.Beep(2400, 150)
                    winsound.Beep(1800, 150)
                    time.sleep(0.05)
            except Exception:
                # If sound device unavailable or non-windows, suppress
                pass

        thread = threading.Thread(target=_siren_worker, daemon=True)
        thread.start()
