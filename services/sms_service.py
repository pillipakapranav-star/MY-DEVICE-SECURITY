"""
Aegis Sentinel - SMS Alert Service
Sends emergency location coordinates and intruder alerts via SMS.
Supports:
1. GSM Serial Modem via AT commands (Pure Offline - NO INTERNET NEEDED)
2. Cloud SMS Gateways (Twilio, Fast2SMS)
3. Offline Outbox Spooler (Queues messages to disk when disconnected)
"""

import time
import json
import datetime
from pathlib import Path
from typing import Optional, List
import serial
import serial.tools.list_ports
import requests
from config import SMS_OUTBOX_FILE
from services.location_service import LocationService


class SMSService:
    """Multi-channel SMS dispatcher with offline GSM hardware modem support."""

    @staticmethod
    def list_available_com_ports() -> List[str]:
        """Detect available COM serial ports (GSM modems, cellular dongles)."""
        ports = serial.tools.list_ports.comports()
        return [p.device for p in ports]

    @staticmethod
    def send_via_gsm_modem(port: str, baud_rate: int, phone_number: str, message: str) -> bool:
        """
        Send SMS directly via hardware GSM/LTE modem using serial AT commands.
        REQUIRES ZERO INTERNET - Works purely via cellular SIM card!
        """
        try:
            print(f"[SMSService] Initializing GSM Modem on {port} (Baud {baud_rate})...")
            with serial.Serial(port, baudrate=baud_rate, timeout=5) as ser:
                time.sleep(0.5)
                # Test AT response
                ser.write(b"AT\r\n")
                time.sleep(0.5)
                ser.read_all()

                # Set SMS text mode
                ser.write(b"AT+CMGF=1\r\n")
                time.sleep(0.5)
                ser.read_all()

                # Initiate SMS sending
                cmd = f'AT+CMGS="{phone_number}"\r\n'
                ser.write(cmd.encode())
                time.sleep(0.5)

                # Send message body terminated by Ctrl+Z (\x1A)
                payload = f"{message}\x1a"
                ser.write(payload.encode("utf-8", errors="replace"))
                time.sleep(3.0)

                resp = ser.read_all().decode("ascii", errors="ignore")
                if "OK" in resp or "+CMGS:" in resp:
                    print(f"[SMSService] [SUCCESS] Offline GSM SMS sent to {phone_number} via {port}!")
                    return True
                else:
                    print(f"[SMSService] GSM modem response: {resp.strip()}")
                    return False
        except Exception as e:
            print(f"[SMSService] [ERROR] GSM Modem transmission failed on {port}: {e}")
            return False

    @staticmethod
    def send_via_twilio(account_sid: str, auth_token: str, from_number: str, to_number: str, message: str) -> bool:
        """Send SMS via Twilio REST API."""
        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            data = {
                "From": from_number,
                "To": to_number,
                "Body": message
            }
            resp = requests.post(url, data=data, auth=(account_sid, auth_token), timeout=8)
            if resp.status_code in [200, 201]:
                print(f"[SMSService] [SUCCESS] Twilio SMS dispatched to {to_number}")
                return True
            else:
                print(f"[SMSService] Twilio API error ({resp.status_code}): {resp.text}")
                return False
        except Exception as e:
            print(f"[SMSService] [ERROR] Twilio dispatch failed: {e}")
            return False

    @staticmethod
    def send_via_fast2sms(api_key: str, phone_number: str, message: str) -> bool:
        """Send SMS via Fast2SMS API (Popular in India / International)."""
        try:
            url = "https://www.fast2sms.com/dev/bulkV2"
            headers = {"authorization": api_key}
            clean_number = "".join(filter(str.isdigit, phone_number))
            if len(clean_number) > 10:
                clean_number = clean_number[-10:]

            payload = {
                "route": "v3",
                "sender_id": "TXTIND",
                "message": message[:159],
                "language": "english",
                "flash": 0,
                "numbers": clean_number
            }
            resp = requests.post(url, json=payload, headers=headers, timeout=8)
            if resp.status_code == 200 and resp.json().get("return") is True:
                print(f"[SMSService] [SUCCESS] Fast2SMS dispatched to {phone_number}")
                return True
            else:
                print(f"[SMSService] Fast2SMS error: {resp.text}")
                return False
        except Exception as e:
            print(f"[SMSService] [ERROR] Fast2SMS dispatch failed: {e}")
            return False

    @staticmethod
    def queue_offline_outbox(phone_number: str, message: str, location: dict):
        """
        Record pending SMS to local disk outbox.
        Ensures alerts are never lost even if all network and hardware modems are disconnected.
        """
        item = {
            "timestamp": datetime.datetime.now().isoformat(),
            "phone_number": phone_number,
            "message": message,
            "location": location,
            "status": "QUEUED_OFFLINE"
        }
        try:
            queue = []
            if SMS_OUTBOX_FILE.exists():
                with open(SMS_OUTBOX_FILE, "r", encoding="utf-8") as f:
                    queue = json.load(f)
            queue.append(item)
            with open(SMS_OUTBOX_FILE, "w", encoding="utf-8") as f:
                json.dump(queue, f, indent=4)

            # Also write human-readable log
            txt_file = SMS_OUTBOX_FILE.with_suffix(".txt")
            with open(txt_file, "a", encoding="utf-8") as f:
                f.write(f"--- [{item['timestamp']}] SMS OUTBOX QUEUE ---\n")
                f.write(f"Target: {phone_number}\n")
                f.write(f"{message}\n\n")

            print(f"[SMSService] [OUTBOX] Emergency SMS spooled to offline queue: {SMS_OUTBOX_FILE.name}")
        except Exception as e:
            print(f"[SMSService] Outbox save error: {e}")

    @staticmethod
    def dispatch_alert_sms(config: dict, location: dict, alert_reason: str = "FAILED PASSWORD") -> bool:
        """
        Master SMS dispatcher.
        Constructs location payload, tries selected provider,
        and automatically falls back to GSM modem or offline queue.
        """
        phone = config.get("target_phone_number", "").strip()
        if not phone:
            print("[SMSService] [WARNING] Target phone number not configured.")
            return False

        message = LocationService.format_sms_text(location, alert_type=alert_reason)
        provider = config.get("sms_provider", "gsm_modem")
        success = False

        if provider == "gsm_modem":
            port = config.get("gsm_com_port", "COM3")
            baud = int(config.get("gsm_baud_rate", 9600))
            success = SMSService.send_via_gsm_modem(port, baud, phone, message)

        elif provider == "twilio":
            sid = config.get("twilio_account_sid", "").strip()
            token = config.get("twilio_auth_token", "").strip()
            from_num = config.get("twilio_from_number", "").strip()
            if sid and token and from_num:
                success = SMSService.send_via_twilio(sid, token, from_num, phone, message)
            else:
                print("[SMSService] Twilio credentials incomplete.")

        elif provider == "fast2sms":
            key = config.get("fast2sms_api_key", "").strip()
            if key:
                success = SMSService.send_via_fast2sms(key, phone, message)
            else:
                print("[SMSService] Fast2SMS key not set.")

        # If online/modem transmission didn't succeed, save to offline outbox
        if not success:
            SMSService.queue_offline_outbox(phone, message, location)

        return success
