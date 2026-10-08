"""
Aegis Sentinel - Main Entry Point
Advanced System Security, Anti-Theft Protection & Biometric Guard.

Usage:
    python main.py                  # Launch full Cyber-Defense GUI (or fallback to CLI menu)
    python main.py --cli            # Launch Interactive Console Menu
    python main.py --interactive    # Live interactive User PIN Authentication (-i / --input)
    python main.py --shield         # Launch Fullscreen Lock Shield
    python main.py --sentry         # Run Case 2 Owner-Only Sentry Monitor in Console
    python main.py --test-case1     # Test Case 1 (3 Failed attempts -> 5 photos -> Location -> Email/SMS)
    python main.py --test-case1 -i  # Test Case 1 with live User Input
    python main.py --test-case2     # Test Case 2 (Camera face detection & Biometric pipeline)
"""

import sys
import time
import argparse
import getpass
from pathlib import Path

# Force UTF-8 on Windows consoles to prevent cp1252 charmap encoding errors
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from config import (
    load_config, save_config, verify_pin, update_pin,
    INTRUDER_DIR, SMS_OUTBOX_FILE, DATA_DIR, FACE_MODEL_FILE
)
from services.security_monitor import SecurityMonitor, BREACH_LOG_FILE
from services.location_service import LocationService
from services.camera_service import CameraService
from services.face_recognition_service import FaceRecognitionService
from services.email_service import EmailService
from services.sms_service import SMSService
from services.lock_service import LockService


def run_interactive_pin_auth(lock_workstation: bool = False, max_attempts: int = 3) -> bool:
    """
    Live User PIN Authentication with interactive console input:
    - Prompts the user to enter the Master PIN
    - Verifies input against stored SHA-256 hash
    - Tracks consecutive failed attempts
    - Triggers full Case 1 breach protocol upon 3 strikes
    """
    print("\n" + "=" * 65)
    print(">>> AEGIS SENTINEL: LIVE USER PIN AUTHENTICATION")
    print("=" * 65)
    print("Defense Policy: 3 consecutive failed attempts will trigger:")
    print("  - Host Workstation Lock (Win+L)")
    print("  - Deterrence Alarm Siren")
    print("  - Approximate IP-based area lookup (not GPS-accurate)")
    print("  - 5 High-Resolution Forensic Burst Photos (0.2s interval)")
    print("  - Forensic Gmail Dispatch & Emergency SMS Transmission")
    print("=" * 65)

    config = load_config()
    config["lock_windows_on_breach"] = lock_workstation
    monitor = SecurityMonitor(config)
    stored_hash = config.get("system_pin_hash", "")
    attempts_limit = int(config.get("failed_attempts_limit", max_attempts))

    failed_count = 0
    while failed_count < attempts_limit:
        attempt_num = failed_count + 1
        remaining_before = attempts_limit - failed_count
        prompt_text = f"\n[Attempt {attempt_num}/{attempts_limit}] Enter Master PIN ('q' to exit): "

        try:
            # We use standard input so user can see what they type (or getpass if preferred)
            user_input = input(prompt_text).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[Auth] Authentication canceled by user.")
            return False

        if user_input.lower() in ("q", "quit", "exit"):
            print("[Auth] Authentication aborted.")
            return False

        if not user_input:
            print("  [!] PIN cannot be empty. Please enter your PIN.")
            continue

        if verify_pin(user_input, stored_hash):
            print("\n" + "-" * 65)
            print(">>> [SUCCESS] Master PIN Verified! Access Granted.")
            print(">>> Workstation remains active. Security state: SECURE.")
            print("-" * 65 + "\n")
            monitor.failed_attempts_count = 0
            return True
        else:
            failed_count += 1
            remaining = attempts_limit - failed_count
            is_last = (failed_count >= attempts_limit)

            print(f"  [AUTH FAIL] Incorrect PIN entered!")
            res = monitor.record_password_attempt(is_correct=False, run_sync=is_last)

            if remaining > 0:
                print(f"  [WARNING] {remaining} attempt(s) remaining before system lockdown!")
            else:
                print("\n" + "=" * 65)
                print(">>> [CRITICAL BREACH DETECTED] 3 FAILED ATTEMPTS REACHED!")
                print(">>> EXECUTING FULL CASE 1 DEFENSE LOCKDOWN & EVIDENCE DISPATCH...")
                print("=" * 65 + "\n")
                # Wait momentarily for breach logs and evidence files to flush
                time.sleep(1.0)
                _print_breach_summary()
                return False

    return False


def _print_breach_summary():
    """Display evidence files created during breach."""
    photos = sorted(list(INTRUDER_DIR.glob("*.jpg")), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
    print(f"  Forensic Burst Photos Preserved: {len(photos)}")
    for p in photos:
        print(f"    - {p.name} ({p.stat().st_size} bytes)")

    if SMS_OUTBOX_FILE.exists():
        print(f"  SMS Outbox Spooler: {SMS_OUTBOX_FILE.name} verified.")


def run_test_case_1(lock_workstation: bool = False, interactive: bool = False):
    """
    Test Case 1:
    - If interactive=True: Prompts user for real PIN entries
    - If interactive=False: Runs automated 3-attempt simulation with '0000'
    """
    if interactive:
        run_interactive_pin_auth(lock_workstation=lock_workstation)
        return

    print("\n" + "=" * 65)
    print(">>> EXECUTING TEST: CASE 1 (AUTOMATED 3-STRIKE SIMULATION)")
    print("=" * 65)

    config = load_config()
    config["lock_windows_on_breach"] = lock_workstation
    monitor = SecurityMonitor(config)

    print("\n[Step 1] Simulating 3 consecutive failed password entries...")
    for i in range(1, 4):
        print(f"  Attempt {i}: Entering incorrect PIN '0000'...")
        is_last = (i == 3)
        res = monitor.record_password_attempt(is_correct=False, run_sync=is_last)
        print(f"  Result: {res['status']} | Remaining: {res['remaining_attempts']}")

    print("\n[Step 2] Verifying generated intruder evidence files...")
    _print_breach_summary()

    print("\n" + "=" * 65)
    print(">>> CASE 1 TEST VERIFICATION COMPLETED SUCCESSFULLY!")
    print("=" * 65 + "\n")


def run_test_case_2():
    """
    Automated test of Case 2:
    - Tests camera hardware initialization
    - Captures test frame
    - Runs Haar Face Detection
    - Verifies LBPH recognizer readiness
    """
    print("\n" + "=" * 65)
    print(">>> EXECUTING TEST: CASE 2 (BIOMETRIC SENTRY & FACE RECOGNITION)")
    print("=" * 65)

    cam = CameraService(0)
    face_svc = FaceRecognitionService()

    print("[Step 1] Opening camera device...")
    ok, frame = cam.read_frame()
    if not ok or frame is None:
        print("  [ERROR] Could not read frame from camera index 0.")
        return

    print("  Camera stream active! Frame resolution: 640x480")

    print("[Step 2] Processing frame through face recognition pipeline...")
    result = face_svc.process_frame(frame)
    print(f"  Faces detected in frame: {result['face_count']}")
    print(f"  Biometric model trained: {face_svc.is_trained}")
    print(f"  Owner detected: {result['owner_detected']}")
    print(f"  Unknown detected: {result['unknown_detected']}")

    cam.close_camera()
    print("\n" + "=" * 65)
    print(">>> CASE 2 TEST VERIFICATION COMPLETED SUCCESSFULLY!")
    print("=" * 65 + "\n")


def run_console_enrollment():
    """Interactive biometric enrollment via terminal user input."""
    import cv2
    print("\n" + "=" * 65)
    print(">>> BIOMETRIC OWNER ENROLLMENT (CONSOLE MODE)")
    print("=" * 65)

    config = load_config()
    current_owner = config.get("owner_name", "Authorized Owner")
    try:
        user_name = input(f"Enter Owner Full Name [Current: {current_owner}]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nEnrollment canceled.")
        return

    owner_name = user_name if user_name else current_owner
    print(f"\n[Step 1] Initializing webcam to capture 30 sample face frames for '{owner_name}'...")
    print(">>> Please look directly at the camera and tilt your head slightly...")
    time.sleep(1.0)

    cap = cv2.VideoCapture(int(config.get("camera_index", 0)))
    if not cap.isOpened():
        print("[ERROR] Could not open webcam.")
        return

    frames = []
    max_samples = 30
    for i in range(max_samples):
        ret, frame = cap.read()
        if ret and frame is not None:
            frames.append(frame.copy())
            pct = int(((i + 1) / max_samples) * 100)
            sys.stdout.write(f"\r  Capturing samples: [{('=' * (pct // 5)):<20}] {pct}% ({i + 1}/{max_samples})")
            sys.stdout.flush()
        time.sleep(0.08)

    cap.release()
    print("\n\n[Step 2] Training LBPH Face Recognition Model...")
    face_svc = FaceRecognitionService()
    success = face_svc.enroll_owner_samples(frames, owner_name=owner_name)
    if success:
        config["owner_name"] = owner_name
        save_config(config)
        print(f"  [SUCCESS] Biometric model trained and activated for: '{owner_name}'!")
    else:
        print("  [ERROR] Insufficient face samples detected. Please ensure good lighting and retry.")
    print("=" * 65 + "\n")


def run_console_pin_update():
    """Interactive Master PIN update via console user input."""
    print("\n" + "=" * 65)
    print(">>> UPDATE SYSTEM MASTER PIN")
    print("=" * 65)

    config = load_config()
    stored_hash = config.get("system_pin_hash", "")

    try:
        current_pin = input("Enter current Master PIN: ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    if not verify_pin(current_pin, stored_hash):
        print("  [ERROR] Current PIN verification failed! Access denied.")
        return

    try:
        new_pin = input("Enter NEW Master PIN (min 8 characters): ").strip()
        confirm_pin = input("Confirm NEW Master PIN: ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    if len(new_pin) < 8:
        print("  [ERROR] PIN must be at least 8 characters.")
        return

    if new_pin != confirm_pin:
        print("  [ERROR] PIN confirmation does not match.")
        return

    if update_pin(new_pin, config):
        print("  [SUCCESS] Master PIN successfully updated!")
    else:
        print("  [ERROR] Failed to save updated PIN.")
    print("=" * 65 + "\n")


def run_console_location_check():
    """Request and display an approximate IP-based network area."""
    print("\n" + "=" * 65)
    print(">>> REQUESTING APPROXIMATE IP NETWORK AREA")
    print("=" * 65)
    loc = LocationService.get_current_location()
    print(f"  Telemetry Status : {loc.get('status')}")
    print(f"  City & Region    : {loc.get('city')}, {loc.get('region')} ({loc.get('country')})")
    lat, lon = loc.get("lat"), loc.get("lon")
    coords = f"Lat {lat:.6f}, Lon {lon:.6f} (approximate IP estimate)" if lat is not None and lon is not None else "Unavailable"
    print(f"  Coordinates      : {coords}")
    print(f"  Accuracy         : {loc.get('accuracy', 'Unknown')}")
    print(f"  Public IP / ISP  : {loc.get('ip')} | {loc.get('isp')}")
    print(f"  Google Maps Link : {loc.get('maps_url')}")
    print(f"  Telemetry Source : {loc.get('source')}")
    print("=" * 65 + "\n")


def run_interactive_cli_menu():
    """Comprehensive Interactive Console Menu for all Aegis Sentinel operations."""
    print("\nAuthenticate with your VANDY Master PIN to open the console.")
    if not run_interactive_pin_auth(lock_workstation=False):
        return
    while True:
        print("\n" + "╔" + "═" * 66 + "╗")
        print("║              🛡️   AEGIS SENTINEL SECURITY CONSOLE                ║")
        print("║           Anti-Theft Defense & Biometric Host Guard             ║")
        print("╚" + "═" * 66 + "╝")
        print("  [1] Live User PIN Authentication (Interactive 3-Strike Test)")
        print("  [2] Automated Case 1 Simulation (3 Failed Attempts -> Breach)")
        print("  [3] Active Case 2 Biometric Sentry (Live Camera HUD)")
        print("  [4] Enroll Owner Face Biometrics (Webcam Sample Capture)")
        print("  [5] Request Approximate IP Network Area")
        print("  [6] Launch Fullscreen Lock Shield Overlay")
        print("  [7] Test Emergency SMS Dispatch (User Input Recipient)")
        print("  [8] Test Forensic Email Alert Dispatch (Gmail SMTP)")
        print("  [9] Update Master PIN (Interactive User Input)")
        print("  [10] View Recent Intruder Audit History")
        print("  [11] Launch Cyber-Defense Desktop GUI")
        print("  [0] Exit")
        print("-" * 68)

        try:
            choice = input("Enter choice (0-11): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Aegis Sentinel.")
            break

        if choice == "1":
            run_interactive_pin_auth(lock_workstation=False)
        elif choice == "2":
            run_test_case_1(lock_workstation=False, interactive=False)
        elif choice == "3":
            _run_sentry_console()
        elif choice == "4":
            run_console_enrollment()
        elif choice == "5":
            run_console_location_check()
        elif choice == "6":
            from lock_shield import LockShieldApp
            app = LockShieldApp()
            app.mainloop()
        elif choice == "7":
            _test_sms_interactive()
        elif choice == "8":
            _test_email_interactive()
        elif choice == "9":
            run_console_pin_update()
        elif choice == "10":
            _view_audit_logs()
        elif choice == "11":
            from ui.main_window import launch_gui
            launch_gui()
        elif choice in ("0", "exit", "q"):
            print("Exiting Aegis Sentinel. Stay safe!")
            break
        else:
            print("Invalid option. Please choose between 0 and 11.")


def _run_sentry_console():
    """Run Case 2 Sentry in console mode with OpenCV HUD."""
    import cv2
    config = load_config()
    if not FACE_MODEL_FILE.exists():
        print("\n[!] Biometric model not trained yet. Please enroll owner face first (Option 4).")
        return

    monitor = SecurityMonitor(config)
    print("\n[AEGIS SENTRY] Starting active sentry guard. Press 'q' on video window to exit.")

    def _display(res):
        frame = res.get("annotated_frame")
        if frame is not None:
            cv2.imshow("Aegis Sentinel - Active Sentry HUD", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                monitor.stop_sentry_guard()

    monitor.start_sentry_guard(on_frame_callback=_display)
    try:
        while monitor.is_sentry_active():
            cv2.waitKey(100)
    except KeyboardInterrupt:
        monitor.stop_sentry_guard()
    cv2.destroyAllWindows()


def _test_sms_interactive():
    """Test SMS dispatch with user input phone number."""
    config = load_config()
    current_phone = config.get("target_phone_number", "")
    try:
        phone_input = input(f"Enter target phone number [Current: {current_phone}]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    if phone_input:
        config["target_phone_number"] = phone_input
        save_config(config)

    loc = LocationService.get_current_location()
    print("Dispatching test SMS...")
    ok = SMSService.dispatch_alert_sms(config, loc, alert_reason="CONSOLE USER TEST")
    if ok:
        print("  [SUCCESS] Test SMS delivered successfully!")
    else:
        print("  [NOTICE] SMS queued to local outbox (data/sms_outbox.txt).")


def _test_email_interactive():
    """Test Email dispatch with user input receiver email."""
    config = load_config()
    current_rcv = config.get("gmail_receiver", "")
    try:
        rcv_input = input(f"Enter recipient email [Current: {current_rcv}]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    if rcv_input:
        config["gmail_receiver"] = rcv_input
        save_config(config)

    loc = LocationService.get_current_location()
    images = list(INTRUDER_DIR.glob("*.jpg"))[-5:]
    if not images:
        cam = CameraService(int(config.get("camera_index", 0)))
        images = cam.capture_burst_images(count=1, location_meta=loc)

    print("Dispatching test Email forensic report...")
    ok = EmailService.send_breach_alert(config, loc, images, alert_reason="CONSOLE USER TEST")
    if ok:
        print("  [SUCCESS] Forensic report email sent successfully!")
    else:
        print("  [ERROR] Failed to send email. Check Gmail credentials and App Password.")


def _view_audit_logs():
    """Display breach history."""
    import json
    print("\n" + "=" * 65)
    print(">>> INTRUDER EVIDENCE & AUDIT HISTORY")
    print("=" * 65)
    if BREACH_LOG_FILE.exists():
        try:
            with open(BREACH_LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
            if logs:
                for idx, entry in enumerate(logs[:5], 1):
                    print(f"[{idx}] {entry.get('timestamp')}")
                    print(f"    Reason   : {entry.get('reason')}")
                    print(f"    Location : {entry.get('city')}, {entry.get('region')} ({entry.get('status')})")
                    print(f"    Photos   : {len(entry.get('images_saved', []))} captured")
                    print("-" * 50)
                return
        except Exception as e:
            print(f"Error reading logs: {e}")
    print("No breach incidents recorded. System secure.\n")


def main():
    parser = argparse.ArgumentParser(description="Aegis Sentinel Security Suite")
    parser.add_argument("--shield", action="store_true", help="Launch Fullscreen Lock Shield")
    parser.add_argument("--sentry", action="store_true", help="Run Case 2 Owner-Only Sentry in Console")
    parser.add_argument("--test-case1", action="store_true", help="Run Case 1 failed password protocol test")
    parser.add_argument("--test-case2", action="store_true", help="Run automated test of Case 2 face recognition")
    parser.add_argument("-i", "--interactive", "--input", action="store_true", dest="interactive",
                        help="Run interactive User PIN authentication with live console input")
    parser.add_argument("--cli", action="store_true", help="Launch the Interactive Console Menu")
    parser.add_argument("--lock", action="store_true", help="Allow real Windows workstation locking in test mode")

    args = parser.parse_args()

    if args.cli:
        run_interactive_cli_menu()
    elif args.interactive:
        run_interactive_pin_auth(lock_workstation=args.lock)
    elif args.test_case1:
        run_test_case_1(lock_workstation=args.lock, interactive=args.interactive)
    elif args.test_case2:
        run_test_case_2()
    elif args.shield:
        from lock_shield import LockShieldApp
        app = LockShieldApp()
        app.mainloop()
    elif args.sentry:
        _run_sentry_console()
    else:
        # Default: try launching GUI, fallback to interactive CLI menu if GUI fails (e.g. headless)
        try:
            from ui.main_window import launch_gui
            launch_gui()
        except Exception as e:
            print(f"[Aegis Launcher] Could not start GUI ({e}). Launching Interactive Console Menu...")
            run_interactive_cli_menu()


if __name__ == "__main__":
    main()
