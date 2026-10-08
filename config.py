"""
Aegis Sentinel - Configuration Module
Manages application settings, persistence, and security parameters.
"""

import os
import json
import hashlib
import hmac
import secrets
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
INTRUDER_DIR = BASE_DIR / "captured_intruders"
SOUNDS_DIR = BASE_DIR / "sounds"
CONFIG_FILE = DATA_DIR / "config.json"
LOCATION_CACHE_FILE = DATA_DIR / "last_location.json"
FACE_MODEL_FILE = DATA_DIR / "owner_model.yml"
FACE_LABELS_FILE = DATA_DIR / "labels.json"
FACE_DATASET_DIR = DATA_DIR / "owner_faces"
SMS_OUTBOX_FILE = DATA_DIR / "sms_outbox.json"
CASCADE_FACE_FILE = DATA_DIR / "haarcascade_frontalface_default.xml"
CASCADE_EYE_FILE = DATA_DIR / "haarcascade_eye.xml"

for d in [DATA_DIR, INTRUDER_DIR, SOUNDS_DIR, FACE_DATASET_DIR]:
    d.mkdir(parents=True, exist_ok=True)

DEFAULT_CONFIG = {
    # Demo credential only. Change this immediately in Settings before use.
    # New hashes use PBKDF2; legacy SHA-256 hashes are upgraded after login.
    "system_pin_hash": hashlib.sha256("1234".encode()).hexdigest(),
    "failed_attempts_limit": 3,
    "lock_windows_on_breach": True,
    "play_alarm_sound": True,
    "alarm_siren_duration_sec": 3,

    # Camera & Burst capture settings
    "camera_index": 0,
    "burst_photo_count": 5,
    "burst_interval_seconds": 0.2,

    # Email notification settings (Gmail SMTP)
    "email_enabled": False,
    "gmail_sender": "",
    "gmail_app_password": "",
    "gmail_receiver": "",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 465,

    # SMS notification settings
    "sms_enabled": False,
    "target_phone_number": "",
    "sms_provider": "gsm_modem",  # 'gsm_modem', 'twilio', 'fast2sms', 'local_outbox'
    "gsm_com_port": "COM3",
    "gsm_baud_rate": 9600,
    "twilio_account_sid": "",
    "twilio_auth_token": "",
    "twilio_from_number": "",
    "fast2sms_api_key": "",

    # Case 2: Owner Presence Sentry Settings
    "sentry_enabled": False,
    "owner_name": "Authorized Owner",
    "face_confidence_threshold": 70.0,  # Lower means closer match in LBPH (distance < 70 is recognized)
    "unknown_face_lock_delay": 1.5,     # Lock if unknown face is visible for 1.5 seconds
    "lock_on_unknown_person": True,
    "lock_on_owner_absent": False,      # Lock if owner steps away
    "sentry_scan_fps": 10
}


def load_config() -> dict:
    """Load configuration from JSON file or return defaults."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                merged = DEFAULT_CONFIG.copy()
                merged.update(data)
                return merged
        except Exception as e:
            print(f"[Config] Error loading config, using defaults: {e}")
    return DEFAULT_CONFIG.copy()


def save_config(config_data: dict) -> bool:
    """Save configuration to JSON file."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4)
        return True
    except Exception as e:
        print(f"[Config] Error saving config: {e}")
        return False


def verify_pin(input_pin: str, current_hash: str) -> bool:
    """Verify PBKDF2 PIN hashes and accept legacy SHA-256 during migration."""
    candidate = input_pin.strip().encode("utf-8")
    if current_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_hex, expected = current_hash.split("$", 3)
            actual = hashlib.pbkdf2_hmac(
                "sha256", candidate, bytes.fromhex(salt_hex), int(iterations)
            ).hex()
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False
    # Backwards compatibility with the original project's SHA-256 PIN.
    if hmac.compare_digest(hashlib.sha256(candidate).hexdigest(), current_hash):
        # Upgrade the on-disk credential after successful legacy verification.
        config = load_config()
        if config.get("system_pin_hash") == current_hash:
            config["system_pin_hash"] = _hash_pin(input_pin)
            save_config(config)
        return True
    return False


def _hash_pin(pin: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 600_000
    digest = hashlib.pbkdf2_hmac("sha256", pin.strip().encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def update_pin(new_pin: str, config_data: dict) -> bool:
    """Update stored PIN hash using salted PBKDF2."""
    if len(new_pin.strip()) < 8:
        return False
    config_data["system_pin_hash"] = _hash_pin(new_pin)
    return save_config(config_data)
