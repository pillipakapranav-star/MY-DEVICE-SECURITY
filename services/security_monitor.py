"""
Aegis Sentinel - Security Monitor Orchestrator
Coordinates Case 1 (3 Failed Password Attempts -> Lock -> Geolocation -> 5 Burst Photos -> Email + SMS)
and Case 2 (Continuous Sentry: Owner-only Presence Access Control).
"""

import time
import json
import threading
import datetime
from pathlib import Path
from typing import Optional, Callable
from config import DATA_DIR, load_config
from services.location_service import LocationService
from services.camera_service import CameraService
from services.lock_service import LockService
from services.email_service import EmailService
from services.sms_service import SMSService
from services.face_recognition_service import FaceRecognitionService

BREACH_LOG_FILE = DATA_DIR / "breach_history.json"


class SecurityMonitor:
    """Central engine managing theft defense, breach responses, and continuous biometric guard."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config if config is not None else load_config()
        self.camera_service = CameraService(camera_index=int(self.config.get("camera_index", 0)))
        self.face_service = FaceRecognitionService(
            confidence_threshold=float(self.config.get("face_confidence_threshold", 70.0))
        )
        self.failed_attempts_count = 0
        self.failed_attempts_limit = int(self.config.get("failed_attempts_limit", 3))

        # Case 2 Sentry state
        self._sentry_running = False
        self._sentry_thread: Optional[threading.Thread] = None
        self._unknown_detected_start: Optional[float] = None
        self.on_sentry_frame_callback: Optional[Callable] = None
        self.on_breach_callback: Optional[Callable] = None

    def reload_config(self):
        """Reload configuration from disk."""
        self.config = load_config()
        self.failed_attempts_limit = int(self.config.get("failed_attempts_limit", 3))
        self.camera_service.camera_index = int(self.config.get("camera_index", 0))
        self.face_service.confidence_threshold = float(self.config.get("face_confidence_threshold", 70.0))
        self.face_service._load_trained_model()

    # ==========================================
    # CASE 1: FAILED PASSWORD DEFENSE
    # ==========================================
    def record_password_attempt(self, is_correct: bool, run_sync: bool = False) -> dict:
        """
        Record a password/PIN entry attempt.
        If incorrect 3 times, triggers Case 1 breach protocol.
        """
        if is_correct:
            self.failed_attempts_count = 0
            return {"status": "SUCCESS", "remaining_attempts": self.failed_attempts_limit, "thread": None}

        self.failed_attempts_count += 1
        remaining = max(0, self.failed_attempts_limit - self.failed_attempts_count)
        print(f"[SecurityMonitor] [AUTH FAIL] Incorrect password. Attempt {self.failed_attempts_count}/{self.failed_attempts_limit}")

        if self.failed_attempts_count >= self.failed_attempts_limit:
            # Trigger full Case 1 protocol
            if run_sync:
                self.execute_case_1_lockout("3 FAILED SYSTEM PASSWORD ATTEMPTS")
                return {"status": "BREACH_TRIGGERED", "remaining_attempts": 0, "thread": None}
            else:
                t = threading.Thread(
                    target=self.execute_case_1_lockout,
                    args=("3 FAILED SYSTEM PASSWORD ATTEMPTS",),
                    daemon=True
                )
                t.start()
                return {"status": "BREACH_TRIGGERED", "remaining_attempts": 0, "thread": t}

        return {"status": "INCORRECT", "remaining_attempts": remaining, "thread": None}

    def execute_case_1_lockout(self, reason: str = "3 FAILED PASSWORD ATTEMPTS"):
        """
        Execute Case 1 complete response workflow:
        1. Lock whole system immediately
        2. Sound deterrence alarm siren
        3. Request approximate network area (IP-based, not GPS)
        4. Capture rapid 5 burst photos (0.2s interval)
        5. Transmit Gmail forensic alert with 5 photos & map link
        6. Transmit SMS with coordinates (GSM Modem offline / Cloud)
        """
        print(f"\n=======================================================")
        print(f"[AEGIS MONITOR] !!! CRITICAL SECURITY BREACH: {reason} !!!")
        print(f"=======================================================\n")

        # Step 1: Sound alarm siren
        if self.config.get("play_alarm_sound", True):
            LockService.play_siren_async(duration_sec=float(self.config.get("alarm_siren_duration_sec", 3)))

        # Step 2: Lock Windows Workstation immediately
        if self.config.get("lock_windows_on_breach", True):
            LockService.lock_workstation()

        # Step 3: Request a network estimate during an explicitly configured breach response.
        print("[Aegis Monitor] [1/4] Requesting approximate IP network area...")
        location = LocationService.get_current_location()

        # Step 4: Capture 5 burst photos within 0.2s
        photo_count = int(self.config.get("burst_photo_count", 5))
        interval = float(self.config.get("burst_interval_seconds", 0.2))
        print(f"[Aegis Monitor] [2/4] Triggering rapid burst photography ({photo_count} shots @ {interval}s)...")
        captured_images = self.camera_service.capture_burst_images(
            count=photo_count,
            interval_sec=interval,
            location_meta=location
        )

        # Step 5: Send Email Alert with 5 images
        if self.config.get("email_enabled", False):
            print("[Aegis Monitor] [3/4] Dispatching forensic report to designated Gmail...")
            EmailService.send_breach_alert(
                config=self.config,
                location=location,
                image_paths=captured_images,
                alert_reason=reason
            )

        # Step 6: Send SMS Alert (Offline GSM Modem or Cloud Gateway)
        if self.config.get("sms_enabled", False):
            print("[Aegis Monitor] [4/4] Dispatching configured emergency SMS...")
            SMSService.dispatch_alert_sms(
                config=self.config,
                location=location,
                alert_reason=reason
            )

        # Record breach event to audit log
        self._log_breach_event(reason, location, captured_images)

        # Reset failed counter after breach execution
        self.failed_attempts_count = 0

        if self.on_breach_callback:
            try:
                self.on_breach_callback(reason, location, captured_images)
            except Exception:
                pass

        print("[Aegis Monitor] Case 1 breach protocol fully executed.\n")

    # ==========================================
    # CASE 2: ACTIVE SENTRY (OWNER PRESENCE)
    # ==========================================
    def start_sentry_guard(self, on_frame_callback: Optional[Callable] = None):
        """Start Case 2 background biometric monitor."""
        if self._sentry_running:
            return
        self.on_sentry_frame_callback = on_frame_callback
        self._sentry_running = True
        self._unknown_detected_start = None
        self._sentry_thread = threading.Thread(target=self._sentry_guard_loop, daemon=True)
        self._sentry_thread.start()
        print("[Aegis Sentry] Active Biometric Guard ENGAGED.")

    def stop_sentry_guard(self):
        """Stop Case 2 background biometric monitor."""
        self._sentry_running = False
        if (self._sentry_thread and self._sentry_thread.is_alive()
                and threading.current_thread() is not self._sentry_thread):
            self._sentry_thread.join(timeout=1.0)
        self.camera_service.close_camera()
        print("[Aegis Sentry] Active Biometric Guard DISENGAGED.")

    def is_sentry_active(self) -> bool:
        return self._sentry_running

    def _sentry_guard_loop(self):
        """Continuous camera analysis loop for owner presence vs unknown person."""
        lock_delay = float(self.config.get("unknown_face_lock_delay", 1.5))
        fps = int(self.config.get("sentry_scan_fps", 10))
        sleep_interval = 1.0 / max(1, fps)

        while self._sentry_running:
            ret, frame = self.camera_service.read_frame()
            if not ret or frame is None:
                time.sleep(0.1)
                continue

            result = self.face_service.process_frame(frame)

            # Send annotated frame to GUI listener
            if self.on_sentry_frame_callback:
                try:
                    self.on_sentry_frame_callback(result)
                except Exception:
                    pass

            # Case 2 Logic:
            # If owner is detected -> keep unlocked! ("if owner of the system is detetcted then dont lock the system")
            if result["owner_detected"]:
                self._unknown_detected_start = None

            # If unknown person is detected -> lock system! ("if the camera detected anothor or unknown person then lock the system")
            elif result["unknown_detected"]:
                now = time.time()
                if self._unknown_detected_start is None:
                    self._unknown_detected_start = now
                elif (now - self._unknown_detected_start) >= lock_delay:
                    print(f"[Aegis Sentry] [LOCKOUT] Unauthorized unknown person in front of screen for {lock_delay}s!")
                    self.stop_sentry_guard()
                    # Trigger lockout and dispatch
                    self.execute_case_1_lockout(reason="CASE 2: UNKNOWN / UNAUTHORIZED PERSON DETECTED AT CONSOLE")
                    break

            time.sleep(sleep_interval)

    def _log_breach_event(self, reason: str, location: dict, images: list):
        """Append incident to persistent JSON breach history."""
        event = {
            "timestamp": datetime.datetime.now().isoformat(),
            "reason": reason,
            "city": location.get("city", "Unknown"),
            "region": location.get("region", "Unknown"),
            "lat": location.get("lat", 0.0),
            "lon": location.get("lon", 0.0),
            "status": location.get("status", "N/A"),
            "images_saved": [str(p) for p in images]
        }
        try:
            history = []
            if BREACH_LOG_FILE.exists():
                with open(BREACH_LOG_FILE, "r", encoding="utf-8") as f:
                    history = json.load(f)
            history.insert(0, event)
            with open(BREACH_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(history[:100], f, indent=4)
        except Exception as e:
            print(f"[SecurityMonitor] Error logging breach event: {e}")
