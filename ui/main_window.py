"""
Aegis Sentinel - Master Control Center & User Interface
Provides intuitive management of:
- Case 1: Failed Password & Theft Defense (3-strikes lock, location, 5 burst photos, SMS/Email)
- Case 2: Biometric Sentry (Owner presence vs unknown intruder detection with live camera HUD)
- Owner Face Biometric Enrollment
- Alert Notifications (Gmail SMTP, Offline GSM Modem SMS, Twilio, Fast2SMS)
- Forensic Intruder Gallery & Audit History
"""

import os
import sys
import time
import json
import threading
import subprocess
from pathlib import Path
from typing import Optional

import cv2
import numpy as np
from PIL import Image, ImageTk
import customtkinter as ctk
from tkinter import messagebox, filedialog

from config import (
    load_config, save_config, update_pin, verify_pin,
    INTRUDER_DIR, DATA_DIR, FACE_MODEL_FILE, SMS_OUTBOX_FILE
)
from services.security_monitor import SecurityMonitor, BREACH_LOG_FILE
from services.location_service import LocationService
from services.email_service import EmailService
from services.sms_service import SMSService
from services.lock_service import LockService

# Appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class InteractivePinDialog(ctk.CTkToplevel):
    """
    Interactive User Input PIN Authentication Dialog.
    Allows testing password authentication and 3-strike breach response live in GUI.
    """

    def __init__(self, parent, config, monitor, on_breach_callback=None,
                 on_success_callback=None, on_cancel_callback=None):
        super().__init__(parent)
        self.config = config
        self.monitor = monitor
        self.on_breach_callback = on_breach_callback
        self.on_success_callback = on_success_callback
        self.on_cancel_callback = on_cancel_callback
        self.attempts_limit = int(self.config.get("failed_attempts_limit", 3))
        self.failed_count = 0

        self.title("AEGIS SENTINEL - VERIFY MASTER PIN")
        self.geometry("520x460")
        self.resizable(False, False)
        self.configure(fg_color="#0b0f19")
        self.attributes("-topmost", True)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkFrame(self, fg_color="#121826", corner_radius=14, border_width=2, border_color="#334155")
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header Badge
        badge = ctk.CTkLabel(
            container,
            text="[ INTERACTIVE PIN AUTHENTICATION ]",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f97316"
        )
        badge.pack(pady=(20, 5))

        title = ctk.CTkLabel(
            container,
            text="Verify Master PIN",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(pady=2)

        desc = ctk.CTkLabel(
            container,
            text="Enter your VANDY Master PIN to continue.\n3 consecutive failures trigger your configured breach response.",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
            justify="center"
        )
        desc.pack(pady=(0, 15))

        # PIN Entry
        entry_frame = ctk.CTkFrame(container, fg_color="transparent")
        entry_frame.pack(pady=10)

        self.entry_pin = ctk.CTkEntry(
            entry_frame,
            placeholder_text="Enter Master PIN",
            show="*",
            width=260,
            height=42,
            font=ctk.CTkFont(size=15),
            justify="center"
        )
        self.entry_pin.pack(side="left", padx=5)
        self.entry_pin.focus_set()
        self.entry_pin.bind("<Return>", lambda e: self._verify())

        self.show_pin = False

        def _toggle_mask():
            self.show_pin = not self.show_pin
            self.entry_pin.configure(show="" if self.show_pin else "*")
            self.btn_mask.configure(text="Hide" if self.show_pin else "Show")

        self.btn_mask = ctk.CTkButton(
            entry_frame,
            text="Show",
            width=65,
            height=42,
            fg_color="#334155",
            hover_color="#475569",
            command=_toggle_mask
        )
        self.btn_mask.pack(side="left", padx=5)

        # Submit button
        self.btn_submit = ctk.CTkButton(
            container,
            text="SUBMIT & VERIFY PIN",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            width=330,
            height=42,
            command=self._verify
        )
        self.btn_submit.pack(pady=12)

        # Status Label
        self.lbl_status = ctk.CTkLabel(
            container,
            text=f"Attempts Allowed: {self.attempts_limit} remaining",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#22c55e"
        )
        self.lbl_status.pack(pady=5)

        # Close / Cancel button
        btn_cancel = ctk.CTkButton(
            container,
            text="Cancel",
            fg_color="transparent",
            border_width=1,
            border_color="#475569",
            text_color="#94a3b8",
            hover_color="#1e293b",
            width=120,
            height=32,
            command=self._cancel
        )
        btn_cancel.pack(pady=(15, 10))

    def _verify(self):
        entered = self.entry_pin.get().strip()
        stored_hash = self.config.get("system_pin_hash", "")

        if verify_pin(entered, stored_hash):
            self.lbl_status.configure(
                text="[SUCCESS] Correct PIN! Access granted. Strikes reset.",
                text_color="#22c55e"
            )
            self.monitor.failed_attempts_count = 0
            self.btn_submit.configure(state="disabled", fg_color="#15803d")
            self.after(500, self._complete_success)
        else:
            self.failed_count += 1
            remaining = max(0, self.attempts_limit - self.failed_count)
            self.entry_pin.delete(0, "end")

            if self.failed_count >= self.attempts_limit:
                self.lbl_status.configure(
                    text="[BREACH!] 3 FAILED ATTEMPTS! EXECUTING LOCKDOWN & EVIDENCE DISPATCH...",
                    text_color="#ef4444"
                )
                self.btn_submit.configure(state="disabled", fg_color="#7f1d1d")
                self.update()

                def _run_lockout():
                    self.monitor.execute_case_1_lockout(reason="3 FAILED USER PIN ATTEMPTS IN GUI DIALOG")
                    if self.on_breach_callback:
                        self.after(0, self.on_breach_callback)

                threading.Thread(target=_run_lockout, daemon=True).start()
                self.after(2000, self.destroy)
            else:
                self.lbl_status.configure(
                    text=f"[INCORRECT PIN] Warning: {remaining} attempt(s) remaining!",
                    text_color="#f59e0b"
                )

    def _complete_success(self):
        self.destroy()
        if self.on_success_callback:
            self.on_success_callback()

    def _cancel(self):
        self.destroy()
        if self.on_cancel_callback:
            self.on_cancel_callback()



class MainWindow(ctk.CTk):
    """Main graphical interface for Aegis Sentinel security suite."""

    def __init__(self):
        super().__init__()

        self.title("VANDY | Aegis Sentinel Security Console")
        self.geometry("1100x720")
        self.minsize(980, 640)
        self.configure(fg_color="#0b0f19")

        self.config = load_config()
        self.monitor = SecurityMonitor(self.config)

        # State
        self.live_camera_active = False
        self.enrollment_in_progress = False

        self._build_layout()
        self._update_system_status_indicators()
        self.withdraw()
        self.after(200, self._authenticate_dashboard)

    def _authenticate_dashboard(self):
        """Require the VANDY PIN before exposing dashboard controls."""
        InteractivePinDialog(
            self,
            self.config,
            self.monitor,
            on_breach_callback=self.destroy,
            on_success_callback=self.deiconify,
            on_cancel_callback=self.destroy,
        )

    def _build_layout(self):
        # Top Header Bar
        self.header_frame = ctk.CTkFrame(self, fg_color="#111827", height=60, corner_radius=0)
        self.header_frame.pack(fill="x", side="top")
        self.header_frame.pack_propagate(False)

        # Header Title
        title_box = ctk.CTkLabel(
            self.header_frame,
            text="VANDY | AEGIS SENTINEL",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#38bdf8"
        )
        title_box.pack(side="left", padx=20)

        sub_title = ctk.CTkLabel(
            self.header_frame,
            text="| Anti-Theft & Biometric Host Defense",
            font=ctk.CTkFont(size=14),
            text_color="#94a3b8"
        )
        sub_title.pack(side="left", padx=(0, 20))

        # Status Badges
        self.badge_case1 = ctk.CTkLabel(
            self.header_frame,
            text="CASE 1: ARMED (3-STRIKES)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#22c55e",
            fg_color="#14532d",
            corner_radius=6,
            padx=10,
            pady=4
        )
        self.badge_case1.pack(side="right", padx=15)

        self.badge_case2 = ctk.CTkLabel(
            self.header_frame,
            text="CASE 2: SENTRY IDLE",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f59e0b",
            fg_color="#78350f",
            corner_radius=6,
            padx=10,
            pady=4
        )
        self.badge_case2.pack(side="right", padx=5)

        # Main Tabview
        self.tabview = ctk.CTkTabview(self, fg_color="#0f172a", segmented_button_selected_color="#2563eb")
        self.tabview.pack(fill="both", expand=True, padx=15, pady=15)

        # Create Tabs
        self.tab_dashboard = self.tabview.add("Dashboard")
        self.tab_sentry = self.tabview.add("Case 2: Biometric Sentry")
        self.tab_enrollment = self.tabview.add("Owner Enrollment")
        self.tab_notifications = self.tabview.add("Alerts (Email & SMS)")
        self.tab_gallery = self.tabview.add("Intruder Gallery & Logs")

        # Build each tab
        self._build_dashboard_tab()
        self._build_sentry_tab()
        self._build_enrollment_tab()
        self._build_notifications_tab()
        self._build_gallery_tab()

    # =========================================================================
    # TAB 1: DASHBOARD
    # =========================================================================
    def _build_dashboard_tab(self):
        tab = self.tab_dashboard

        # Left Column: Case 1 Failed Password Defense
        col_left = ctk.CTkFrame(tab, fg_color="#1e293b", corner_radius=12)
        col_left.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        lbl_c1 = ctk.CTkLabel(
            col_left,
            text="CASE 1: PASSWORD DEFENSE & THEFT MONITOR",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#38bdf8"
        )
        lbl_c1.pack(anchor="w", padx=20, pady=(20, 10))

        desc_c1 = ctk.CTkLabel(
            col_left,
            text="If the VANDY shield PIN fails 3 times:\n"
                 "- VANDY can request a Windows workstation lock\n"
                 "- An approximate IP network area may be queried (not GPS)\n"
                 "- 5 rapid burst photos captured within 0.2s\n"
                 "- Forensic report emailed to Gmail with photos\n"
                 "- SMS dispatched to mobile (GSM Modem / SMS API)",
            font=ctk.CTkFont(size=13),
            text_color="#cbd5e1",
            justify="left"
        )
        desc_c1.pack(anchor="w", padx=20, pady=5)

        # Interactive controls for Case 1
        btn_c1_interactive = ctk.CTkButton(
            col_left,
            text="Interactive PIN Entry Test (User Input)",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#ea580c",
            hover_color="#c2410c",
            height=40,
            command=self._open_interactive_pin_dialog
        )
        btn_c1_interactive.pack(fill="x", padx=20, pady=(25, 8))

        btn_c1_sim = ctk.CTkButton(
            col_left,
            text="Simulate 3 Failed Attempts (Automated Test)",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            height=36,
            command=self._test_case_1_flow
        )
        btn_c1_sim.pack(fill="x", padx=20, pady=8)

        btn_c1_shield = ctk.CTkButton(
            col_left,
            text="Launch Fullscreen Lock Shield",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#4338ca",
            hover_color="#3730a3",
            height=36,
            command=self._launch_shield_overlay
        )
        btn_c1_shield.pack(fill="x", padx=20, pady=10)

        btn_c1_lock_win = ctk.CTkButton(
            col_left,
            text="Direct Windows Lock (Win+L API)",
            font=ctk.CTkFont(size=13),
            fg_color="#334155",
            hover_color="#475569",
            height=34,
            command=LockService.lock_workstation
        )
        btn_c1_lock_win.pack(fill="x", padx=20, pady=10)

        # Right Column: Quick Status & Geolocation Preview
        col_right = ctk.CTkFrame(tab, fg_color="#1e293b", corner_radius=12)
        col_right.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        lbl_loc = ctk.CTkLabel(
            col_right,
            text="HOST GEOLOCATION & HARDWARE STATUS",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#38bdf8"
        )
        lbl_loc.pack(anchor="w", padx=20, pady=(20, 10))

        self.lbl_geo_details = ctk.CTkLabel(
            col_right,
            text="Location is not queried automatically. Use Refresh to request an approximate IP area.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8",
            justify="left"
        )
        self.lbl_geo_details.pack(anchor="w", padx=20, pady=5)

        btn_refresh_loc = ctk.CTkButton(
            col_right,
            text="Request Approximate Network Area",
            font=ctk.CTkFont(size=13),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=34,
            command=self._refresh_location_display
        )
        btn_refresh_loc.pack(anchor="w", padx=20, pady=(15, 10))

        # Location lookup is user-triggered so opening the dashboard makes no location request.

    # =========================================================================
    # TAB 2: CASE 2 BIOMETRIC SENTRY (OWNER-ONLY ACCESS CONTROL)
    # =========================================================================
    def _build_sentry_tab(self):
        tab = self.tab_sentry

        # Controls Bar
        ctrl_frame = ctk.CTkFrame(tab, fg_color="#1e293b", height=70)
        ctrl_frame.pack(fill="x", padx=10, pady=(10, 5))

        self.btn_toggle_sentry = ctk.CTkButton(
            ctrl_frame,
            text="ACTIVATE BIOMETRIC SENTRY",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#16a34a",
            hover_color="#15803d",
            width=260,
            height=44,
            command=self._toggle_sentry_mode
        )
        self.btn_toggle_sentry.pack(side="left", padx=20, pady=12)

        self.lbl_sentry_status = ctk.CTkLabel(
            ctrl_frame,
            text="Sentry Guard is Standby. Click to arm.",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#94a3b8"
        )
        self.lbl_sentry_status.pack(side="left", padx=15)

        # Video Canvas Container
        self.video_container = ctk.CTkFrame(tab, fg_color="#020617", corner_radius=12)
        self.video_container.pack(fill="both", expand=True, padx=10, pady=10)

        self.video_label = ctk.CTkLabel(
            self.video_container,
            text="Camera stream inactive.\nActivate Biometric Sentry above to begin continuous owner-only monitoring.",
            font=ctk.CTkFont(size=15),
            text_color="#64748b"
        )
        self.video_label.pack(fill="both", expand=True, padx=10, pady=10)

    # =========================================================================
    # TAB 3: OWNER ENROLLMENT
    # =========================================================================
    def _build_enrollment_tab(self):
        tab = self.tab_enrollment

        left_panel = ctk.CTkFrame(tab, fg_color="#1e293b", width=360, corner_radius=12)
        left_panel.pack(side="left", fill="y", padx=10, pady=10)
        left_panel.pack_propagate(False)

        lbl_enr = ctk.CTkLabel(
            left_panel,
            text="BIOMETRIC ENROLLMENT",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#38bdf8"
        )
        lbl_enr.pack(anchor="w", padx=20, pady=(20, 10))

        lbl_instruct = ctk.CTkLabel(
            left_panel,
            text="Enroll authorized system owner.\n"
                 "The system will capture 30 sample frames\n"
                 "to train a local LBPH facial model.\n\n"
                 "Tip: Slowly tilt and turn your face\n"
                 "slightly during capture for best accuracy.",
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1",
            justify="left"
        )
        lbl_instruct.pack(anchor="w", padx=20, pady=5)

        self.entry_owner_name = ctk.CTkEntry(
            left_panel,
            placeholder_text="Owner Full Name",
            font=ctk.CTkFont(size=13),
            height=38
        )
        self.entry_owner_name.pack(fill="x", padx=20, pady=(15, 10))
        self.entry_owner_name.insert(0, self.config.get("owner_name", "Authorized Owner"))

        self.btn_start_enroll = ctk.CTkButton(
            left_panel,
            text="Capture & Train Owner Face",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            height=40,
            command=self._start_biometric_enrollment
        )
        self.btn_start_enroll.pack(fill="x", padx=20, pady=10)

        self.enroll_progress = ctk.CTkProgressBar(left_panel, mode="determinate")
        self.enroll_progress.pack(fill="x", padx=20, pady=10)
        self.enroll_progress.set(0)

        self.lbl_enroll_status = ctk.CTkLabel(
            left_panel,
            text=f"Model Status: {'Trained & Active' if FACE_MODEL_FILE.exists() else 'Not Trained'}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#22c55e" if FACE_MODEL_FILE.exists() else "#ef4444"
        )
        self.lbl_enroll_status.pack(anchor="w", padx=20, pady=10)

        # Right Preview Screen
        self.enroll_preview_frame = ctk.CTkFrame(tab, fg_color="#020617", corner_radius=12)
        self.enroll_preview_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        self.enroll_preview_label = ctk.CTkLabel(
            self.enroll_preview_frame,
            text="Camera preview will display during enrollment.",
            font=ctk.CTkFont(size=14),
            text_color="#64748b"
        )
        self.enroll_preview_label.pack(fill="both", expand=True)

    # =========================================================================
    # TAB 4: ALERTS (EMAIL & SMS CONFIGURATION)
    # =========================================================================
    def _build_notifications_tab(self):
        tab = self.tab_notifications

        # Scrollable container
        scroll = ctk.CTkScrollableFrame(tab, fg_color="#0f172a")
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        # Section 1: Gmail SMTP Setup
        gmail_box = ctk.CTkFrame(scroll, fg_color="#1e293b", corner_radius=12)
        gmail_box.pack(fill="x", padx=10, pady=10)

        lbl_g = ctk.CTkLabel(
            gmail_box,
            text="GMAIL FORENSIC REPORT DISPATCH (SMTP)",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#38bdf8"
        )
        lbl_g.pack(anchor="w", padx=20, pady=(15, 5))

        lbl_g_sub = ctk.CTkLabel(
            gmail_box,
            text="Optional breach reports can include captured photos and an approximate IP-based map area (not GPS).",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        lbl_g_sub.pack(anchor="w", padx=20, pady=(0, 10))

        self.chk_email_alerts = ctk.CTkCheckBox(
            gmail_box, text="Enable automatic email on a breach (off by default)",
            text_color="#cbd5e1"
        )
        self.chk_email_alerts.pack(anchor="w", padx=20, pady=(0, 8))
        if self.config.get("email_enabled", False):
            self.chk_email_alerts.select()

        # Fields
        f_row1 = ctk.CTkFrame(gmail_box, fg_color="transparent")
        f_row1.pack(fill="x", padx=20, pady=5)

        self.entry_gmail_sender = ctk.CTkEntry(f_row1, placeholder_text="Sender Gmail Address (e.g. alert@gmail.com)", width=320)
        self.entry_gmail_sender.pack(side="left", padx=(0, 10))
        self.entry_gmail_sender.insert(0, self.config.get("gmail_sender", ""))

        self.entry_gmail_app_pw = ctk.CTkEntry(f_row1, placeholder_text="Gmail 16-Char App Password", show="*", width=260)
        self.entry_gmail_app_pw.pack(side="left", padx=10)
        self.entry_gmail_app_pw.insert(0, self.config.get("gmail_app_password", ""))

        f_row2 = ctk.CTkFrame(gmail_box, fg_color="transparent")
        f_row2.pack(fill="x", padx=20, pady=5)

        self.entry_gmail_receiver = ctk.CTkEntry(f_row2, placeholder_text="Receiver Email (Where alert is delivered)", width=320)
        self.entry_gmail_receiver.pack(side="left", padx=(0, 10))
        self.entry_gmail_receiver.insert(0, self.config.get("gmail_receiver", ""))

        btn_test_email = ctk.CTkButton(
            f_row2,
            text="Send Test Email Alert",
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            width=200,
            command=self._send_test_email
        )
        btn_test_email.pack(side="left", padx=10)

        # Section 2: SMS Configuration (Offline GSM Modem / Cloud Gateway)
        sms_box = ctk.CTkFrame(scroll, fg_color="#1e293b", corner_radius=12)
        sms_box.pack(fill="x", padx=10, pady=15)

        lbl_s = ctk.CTkLabel(
            sms_box,
            text="EMERGENCY SMS & OFFLINE CELLULAR DISPATCH",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#38bdf8"
        )
        lbl_s.pack(anchor="w", padx=20, pady=(15, 5))

        lbl_s_sub = ctk.CTkLabel(
            sms_box,
            text="Transmits location via SMS. For offline use (no internet access), select GSM Modem via USB/COM port.",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        lbl_s_sub.pack(anchor="w", padx=20, pady=(0, 10))

        self.chk_sms_alerts = ctk.CTkCheckBox(
            sms_box, text="Enable automatic SMS on a breach (off by default)",
            text_color="#cbd5e1"
        )
        self.chk_sms_alerts.pack(anchor="w", padx=20, pady=(0, 8))
        if self.config.get("sms_enabled", False):
            self.chk_sms_alerts.select()

        s_row1 = ctk.CTkFrame(sms_box, fg_color="transparent")
        s_row1.pack(fill="x", padx=20, pady=5)

        self.entry_target_phone = ctk.CTkEntry(s_row1, placeholder_text="Target Phone Number (e.g. +919876543210)", width=280)
        self.entry_target_phone.pack(side="left", padx=(0, 10))
        self.entry_target_phone.insert(0, self.config.get("target_phone_number", ""))

        self.combo_sms_provider = ctk.CTkComboBox(
            s_row1,
            values=["gsm_modem", "twilio", "fast2sms", "local_outbox"],
            width=180
        )
        self.combo_sms_provider.pack(side="left", padx=10)
        self.combo_sms_provider.set(self.config.get("sms_provider", "gsm_modem"))

        # GSM Port settings
        s_row_gsm = ctk.CTkFrame(sms_box, fg_color="transparent")
        s_row_gsm.pack(fill="x", padx=20, pady=5)

        detected_ports = SMSService.list_available_com_ports() or ["COM3"]
        self.combo_gsm_port = ctk.CTkComboBox(s_row_gsm, values=detected_ports, width=160)
        self.combo_gsm_port.pack(side="left", padx=(0, 10))
        self.combo_gsm_port.set(self.config.get("gsm_com_port", detected_ports[0]))

        self.entry_gsm_baud = ctk.CTkEntry(s_row_gsm, placeholder_text="Baud (9600)", width=120)
        self.entry_gsm_baud.pack(side="left", padx=10)
        self.entry_gsm_baud.insert(0, str(self.config.get("gsm_baud_rate", 9600)))

        btn_test_sms = ctk.CTkButton(
            s_row_gsm,
            text="Send Test Emergency SMS",
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=200,
            command=self._send_test_sms
        )
        btn_test_sms.pack(side="left", padx=10)

        # Cloud Gateway Credentials (Twilio & Fast2SMS)
        lbl_cloud = ctk.CTkLabel(
            sms_box,
            text="Cloud SMS Credentials (Twilio / Fast2SMS API)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#94a3b8"
        )
        lbl_cloud.pack(anchor="w", padx=20, pady=(10, 2))

        s_row_twilio = ctk.CTkFrame(sms_box, fg_color="transparent")
        s_row_twilio.pack(fill="x", padx=20, pady=5)

        self.entry_twilio_sid = ctk.CTkEntry(s_row_twilio, placeholder_text="Twilio Account SID", width=220)
        self.entry_twilio_sid.pack(side="left", padx=(0, 10))
        self.entry_twilio_sid.insert(0, self.config.get("twilio_account_sid", ""))

        self.entry_twilio_token = ctk.CTkEntry(s_row_twilio, placeholder_text="Twilio Auth Token", show="*", width=200)
        self.entry_twilio_token.pack(side="left", padx=10)
        self.entry_twilio_token.insert(0, self.config.get("twilio_auth_token", ""))

        self.entry_twilio_from = ctk.CTkEntry(s_row_twilio, placeholder_text="Twilio From Phone", width=180)
        self.entry_twilio_from.pack(side="left", padx=10)
        self.entry_twilio_from.insert(0, self.config.get("twilio_from_number", ""))

        s_row_f2s = ctk.CTkFrame(sms_box, fg_color="transparent")
        s_row_f2s.pack(fill="x", padx=20, pady=5)

        self.entry_fast2sms_key = ctk.CTkEntry(s_row_f2s, placeholder_text="Fast2SMS API Key", show="*", width=340)
        self.entry_fast2sms_key.pack(side="left", padx=(0, 10))
        self.entry_fast2sms_key.insert(0, self.config.get("fast2sms_api_key", ""))

        # Section 3: Master PIN Security
        pin_box = ctk.CTkFrame(scroll, fg_color="#1e293b", corner_radius=12)
        pin_box.pack(fill="x", padx=10, pady=15)

        lbl_p = ctk.CTkLabel(
            pin_box,
            text="MASTER PIN & BREACH POLICIES",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#38bdf8"
        )
        lbl_p.pack(anchor="w", padx=20, pady=(15, 5))

        p_row = ctk.CTkFrame(pin_box, fg_color="transparent")
        p_row.pack(fill="x", padx=20, pady=10)

        self.entry_new_pin = ctk.CTkEntry(p_row, placeholder_text="New Master PIN (8+ characters)", show="*", width=240)
        self.entry_new_pin.pack(side="left", padx=(0, 10))

        btn_change_pin = ctk.CTkButton(
            p_row,
            text="Update Master PIN",
            fg_color="#334155",
            hover_color="#475569",
            width=160,
            command=self._update_master_pin
        )
        btn_change_pin.pack(side="left", padx=10)

        btn_save_all = ctk.CTkButton(
            pin_box,
            text="SAVE ALL SETTINGS",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#16a34a",
            hover_color="#15803d",
            height=42,
            command=self._save_all_settings
        )
        btn_save_all.pack(fill="x", padx=20, pady=(15, 20))

    # =========================================================================
    # TAB 5: INTRUDER GALLERY & AUDIT LOGS
    # =========================================================================
    def _build_gallery_tab(self):
        tab = self.tab_gallery

        top_bar = ctk.CTkFrame(tab, fg_color="#1e293b", height=50)
        top_bar.pack(fill="x", padx=10, pady=10)

        lbl_g = ctk.CTkLabel(
            top_bar,
            text="FORENSIC INTRUDER PHOTOS & BREACH TIMELINE",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#38bdf8"
        )
        lbl_g.pack(side="left", padx=20)

        btn_open_folder = ctk.CTkButton(
            top_bar,
            text="Open Intruders Folder",
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            width=180,
            command=lambda: os.startfile(str(INTRUDER_DIR)) if sys.platform == "win32" else None
        )
        btn_open_folder.pack(side="right", padx=15)

        btn_refresh_gal = ctk.CTkButton(
            top_bar,
            text="Refresh History",
            fg_color="#334155",
            hover_color="#475569",
            width=140,
            command=self._load_gallery_data
        )
        btn_refresh_gal.pack(side="right", padx=5)

        # Log content text / preview
        self.txt_breach_logs = ctk.CTkTextbox(tab, font=ctk.CTkFont(family="Consolas", size=12), fg_color="#020617")
        self.txt_breach_logs.pack(fill="both", expand=True, padx=10, pady=10)

        self._load_gallery_data()

    # =========================================================================
    # ACTION HANDLERS & LOGIC
    # =========================================================================
    def _update_system_status_indicators(self):
        if self.monitor.is_sentry_active():
            self.badge_case2.configure(text="CASE 2: SENTRY ACTIVE", text_color="#22c55e", fg_color="#14532d")
        else:
            self.badge_case2.configure(text="CASE 2: SENTRY IDLE", text_color="#f59e0b", fg_color="#78350f")

    def _refresh_location_display(self):
        self.lbl_geo_details.configure(text="Requesting an approximate IP-based area...")
        loc = LocationService.get_current_location()
        lat, lon = loc.get("lat"), loc.get("lon")
        coordinates = f"{lat:.6f}, {lon:.6f} (approximate IP estimate)" if lat is not None and lon is not None else "Unavailable"
        summary = (
            f"Status: {loc.get('status', 'N/A')}\n"
            f"City: {loc.get('city')}, {loc.get('region')} ({loc.get('country')})\n"
            f"Coordinates: {coordinates}\n"
            f"Accuracy: {loc.get('accuracy', 'Unknown')}\n"
            f"Public IP: {loc.get('ip')}\n"
            f"ISP: {loc.get('isp')}\n"
            f"Provider Source: {loc.get('source')}\n"
            f"Last Ping: {loc.get('timestamp')}"
        )
        self.lbl_geo_details.configure(text=summary)

    def _open_interactive_pin_dialog(self):
        """Open the interactive PIN authentication dialog for live testing."""
        InteractivePinDialog(
            parent=self,
            config=self.config,
            monitor=self.monitor,
            on_breach_callback=self._load_gallery_data
        )

    def _test_case_1_flow(self):
        """Execute test of Case 1 (3 failed attempts simulation)."""
        res = messagebox.askyesno(
            "Test Case 1 Breach Defense",
            "This will execute the full Case 1 protocol:\n"
            "1. Acquire current location\n"
            "2. Capture 5 rapid burst photos via webcam\n"
            "3. Dispatch Email & SMS alert\n"
            "4. Lock Windows Workstation\n\n"
            "Proceed with test?"
        )
        if not res:
            return

        def _run():
            self.monitor.execute_case_1_lockout(reason="TEST SIMULATION: 3 FAILED PASSWORD ATTEMPTS")
            self.after(500, self._load_gallery_data)

        threading.Thread(target=_run, daemon=True).start()

    def _launch_shield_overlay(self):
        """Launch the full-screen secure lock shield."""
        shield_script = Path(__file__).resolve().parent.parent / "lock_shield.py"
        subprocess.Popen([sys.executable, str(shield_script)])

    def _toggle_sentry_mode(self):
        """Start or stop Case 2 Biometric Sentry Guard."""
        if not self.monitor.is_sentry_active():
            if not FACE_MODEL_FILE.exists():
                messagebox.showwarning(
                    "Biometric Model Missing",
                    "Please enroll the owner face first in the 'Owner Enrollment' tab before starting Sentry Guard."
                )
                return

            self.btn_toggle_sentry.configure(
                text="DEACTIVATE BIOMETRIC SENTRY",
                fg_color="#dc2626",
                hover_color="#b91c1c"
            )
            self.lbl_sentry_status.configure(
                text="[ACTIVE] SENTRY GUARD RUNNING - ACCESS LIMITED TO OWNER ONLY",
                text_color="#22c55e"
            )
            self.monitor.start_sentry_guard(on_frame_callback=self._on_sentry_frame_received)
            self._update_system_status_indicators()
        else:
            self.monitor.stop_sentry_guard()
            self.btn_toggle_sentry.configure(
                text="ACTIVATE BIOMETRIC SENTRY",
                fg_color="#16a34a",
                hover_color="#15803d"
            )
            self.lbl_sentry_status.configure(
                text="Sentry Guard is Standby. Click to arm.",
                text_color="#94a3b8"
            )
            self.video_label.configure(image="", text="Sentry stream stopped.")
            self._update_system_status_indicators()

    def _on_sentry_frame_received(self, result: dict):
        """Callback displaying annotated HUD frame in Sentry Tab."""
        frame = result.get("annotated_frame")
        if frame is not None:
            # Resize for GUI display
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb)
            img_resized = img.resize((700, 480), Image.Resampling.BILINEAR)
            img_tk = ImageTk.PhotoImage(img_resized)

            def _update():
                self.video_label.configure(image=img_tk, text="")
                self.video_label.image = img_tk

            self.after(0, _update)

    def _start_biometric_enrollment(self):
        """Captures 30 frames from camera and trains owner model."""
        owner_name = self.entry_owner_name.get().strip() or "Authorized Owner"
        self.btn_start_enroll.configure(state="disabled", text="Capturing Samples...")
        self.enroll_progress.set(0)

        def _worker():
            cap = cv2.VideoCapture(int(self.config.get("camera_index", 0)))
            frames = []
            max_samples = 30

            for i in range(max_samples):
                ret, frame = cap.read()
                if ret and frame is not None:
                    frames.append(frame.copy())
                    pct = (i + 1) / max_samples
                    self.after(0, lambda p=pct: self.enroll_progress.set(p))

                    # Update preview
                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(rgb).resize((500, 360), Image.Resampling.BILINEAR)
                    img_tk = ImageTk.PhotoImage(img)
                    self.after(0, lambda im=img_tk: self._show_enroll_preview(im))

                time.sleep(0.08)

            cap.release()

            # Train model
            self.after(0, lambda: self.btn_start_enroll.configure(text="Training LBPH Model..."))
            success = self.monitor.face_service.enroll_owner_samples(frames, owner_name=owner_name)

            def _finish():
                self.btn_start_enroll.configure(state="normal", text="Capture & Train Owner Face")
                if success:
                    self.lbl_enroll_status.configure(
                        text=f"Model Status: Trained & Active for '{owner_name}'",
                        text_color="#22c55e"
                    )
                    self.config["owner_name"] = owner_name
                    save_config(self.config)
                    messagebox.showinfo("Enrollment Successful", f"Biometric model trained successfully for {owner_name}!")
                else:
                    messagebox.showerror("Enrollment Failed", "Could not detect sufficient face samples. Please ensure good lighting.")

            self.after(0, _finish)

        threading.Thread(target=_worker, daemon=True).start()

    def _show_enroll_preview(self, img_tk):
        self.enroll_preview_label.configure(image=img_tk, text="")
        self.enroll_preview_label.image = img_tk

    def _send_test_email(self):
        """Test Gmail dispatch."""
        self._sync_config_from_inputs()
        loc = LocationService.get_current_location()

        def _run():
            # Find an existing intruder photo or capture one frame
            images = list(INTRUDER_DIR.glob("*.jpg"))[-5:]
            if not images:
                images = self.monitor.camera_service.capture_burst_images(count=1, location_meta=loc)

            ok = EmailService.send_breach_alert(
                config=self.config,
                location=loc,
                image_paths=images,
                alert_reason="MANUAL TEST TRANSMISSION"
            )
            if ok:
                self.after(0, lambda: messagebox.showinfo("Email Sent", "Test alert email delivered successfully!"))
            else:
                self.after(0, lambda: messagebox.showerror("Email Error", "Could not deliver email. Check Gmail credentials / App Password."))

        threading.Thread(target=_run, daemon=True).start()

    def _send_test_sms(self):
        """Test SMS dispatch."""
        self._sync_config_from_inputs()
        loc = LocationService.get_current_location()

        def _run():
            ok = SMSService.dispatch_alert_sms(self.config, loc, alert_reason="MANUAL TEST")
            if ok:
                self.after(0, lambda: messagebox.showinfo("SMS Sent", "Emergency SMS dispatched successfully!"))
            else:
                self.after(0, lambda: messagebox.showinfo(
                    "SMS Notice",
                    "SMS queued to local outbox (or hardware GSM modem not attached).\nCheck data/sms_outbox.txt."
                ))

        threading.Thread(target=_run, daemon=True).start()

    def _update_master_pin(self):
        pin = self.entry_new_pin.get().strip()
        if len(pin) < 8:
            messagebox.showwarning("PIN Invalid", "PIN must be at least 8 characters.")
            return
        if not update_pin(pin, self.config):
            messagebox.showerror("PIN Update Failed", "Could not save the new PIN. Check file permissions and try again.")
            return
        self.entry_new_pin.delete(0, "end")
        messagebox.showinfo("PIN Updated", "Master PIN updated successfully.")

    def _sync_config_from_inputs(self):
        self.config["email_enabled"] = bool(self.chk_email_alerts.get())
        self.config["sms_enabled"] = bool(self.chk_sms_alerts.get())
        self.config["gmail_sender"] = self.entry_gmail_sender.get().strip()
        self.config["gmail_app_password"] = self.entry_gmail_app_pw.get().strip()
        self.config["gmail_receiver"] = self.entry_gmail_receiver.get().strip()
        self.config["target_phone_number"] = self.entry_target_phone.get().strip()
        self.config["sms_provider"] = self.combo_sms_provider.get()
        self.config["gsm_com_port"] = self.combo_gsm_port.get()
        try:
            self.config["gsm_baud_rate"] = int(self.entry_gsm_baud.get().strip())
        except ValueError:
            self.config["gsm_baud_rate"] = 9600
        self.config["twilio_account_sid"] = self.entry_twilio_sid.get().strip()
        self.config["twilio_auth_token"] = self.entry_twilio_token.get().strip()
        self.config["twilio_from_number"] = self.entry_twilio_from.get().strip()
        self.config["fast2sms_api_key"] = self.entry_fast2sms_key.get().strip()

    def _save_all_settings(self):
        self._sync_config_from_inputs()
        if save_config(self.config):
            self.monitor.reload_config()
            messagebox.showinfo("Settings Saved", "All configurations saved successfully.")
        else:
            messagebox.showerror("Error", "Could not save configuration.")

    def _load_gallery_data(self):
        """Populate the audit history log."""
        self.txt_breach_logs.delete("1.0", "end")
        if BREACH_LOG_FILE.exists():
            try:
                with open(BREACH_LOG_FILE, "r", encoding="utf-8") as f:
                    logs = json.load(f)
                header = (
                    f"{'TIMESTAMP':<24} | {'INCIDENT TYPE':<38} | {'CITY / REGION':<25} | {'PHOTOS'}\n"
                    f"{'-'*105}\n"
                )
                self.txt_breach_logs.insert("end", header)
                for entry in logs:
                    ts = entry.get("timestamp", "")[:19]
                    reason = entry.get("reason", "Breach")[:36]
                    loc = f"{entry.get('city')}, {entry.get('region')}"[:24]
                    photos = len(entry.get("images_saved", []))
                    line = f"{ts:<24} | {reason:<38} | {loc:<25} | {photos} captured\n"
                    self.txt_breach_logs.insert("end", line)
                return
            except Exception as e:
                self.txt_breach_logs.insert("end", f"Error reading logs: {e}\n")

        self.txt_breach_logs.insert("end", "No breach incidents logged yet. System secure.\n")


def launch_gui():
    """Launch the main GUI desktop application."""
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
