"""
Aegis Sentinel - Fullscreen Lock Shield
A secure lockout interface that enforces the 3-strikes password rule.
Triggers the configured incident response after 3 failures. Network location
is approximate IP data, not GPS.
"""

import sys
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from config import load_config, verify_pin
from services.security_monitor import SecurityMonitor

# Force Dark theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LockShieldApp(ctk.CTk):
    """Secure full-screen lock overlay for Case 1 failed password enforcement."""

    def __init__(self):
        super().__init__()

        self.config = load_config()
        self.monitor = SecurityMonitor(self.config)
        self.attempts_limit = int(self.config.get("failed_attempts_limit", 3))
        self.failed_count = 0

        # Window styling
        self.title("VANDY | AEGIS SENTINEL - LOCK SHIELD")
        self.attributes("-fullscreen", True)
        self.attributes("-topmost", True)
        self.configure(fg_color="#090d16")

        # Disable Alt+F4
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        self.bind("<Escape>", lambda e: None)

        self._build_ui()

    def _build_ui(self):
        # Center container
        self.center_frame = ctk.CTkFrame(self, fg_color="#121826", corner_radius=16, border_width=2, border_color="#1e293b", width=520, height=480)
        self.center_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.center_frame.pack_propagate(False)

        # Top Badge / Icon
        self.shield_badge = ctk.CTkLabel(
            self.center_frame,
            text="[ AEGIS ACTIVE DEFENSE ]",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        )
        self.shield_badge.pack(pady=(35, 10))

        # Title
        self.title_label = ctk.CTkLabel(
            self.center_frame,
            text="WORKSTATION LOCKED",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="#f8fafc"
        )
        self.title_label.pack(pady=5)

        self.sub_label = ctk.CTkLabel(
            self.center_frame,
            text="Authorized Master PIN Required to Access System",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        )
        self.sub_label.pack(pady=(0, 20))

        # PIN Entry
        self.pin_entry = ctk.CTkEntry(
            self.center_frame,
            placeholder_text="Enter your Master PIN",
            show="*",
            width=320,
            height=46,
            font=ctk.CTkFont(size=16),
            justify="center",
            fg_color="#1e293b",
            border_color="#334155"
        )
        self.pin_entry.pack(pady=10)
        self.pin_entry.focus_set()
        self.pin_entry.bind("<Return>", lambda e: self._attempt_unlock())

        # Unlock Button
        self.unlock_btn = ctk.CTkButton(
            self.center_frame,
            text="AUTHENTICATE & UNLOCK",
            width=320,
            height=44,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            command=self._attempt_unlock
        )
        self.unlock_btn.pack(pady=15)

        # Status / Attempts remaining label
        self.status_label = ctk.CTkLabel(
            self.center_frame,
            text=f"Failed Attempts Allowed: {self.attempts_limit} remaining",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#22c55e"
        )
        self.status_label.pack(pady=10)

        # Emergency Warning note
        self.warning_label = ctk.CTkLabel(
            self.center_frame,
            text="NOTICE: 3 failed attempts trigger the configured response.\nLocation is approximate IP data, not GPS. Camera and alerts need setup.",
            font=ctk.CTkFont(size=11),
            text_color="#64748b",
            justify="center"
        )
        self.warning_label.pack(side="bottom", pady=20)

    def _attempt_unlock(self):
        entered = self.pin_entry.get().strip()
        stored_hash = self.config.get("system_pin_hash", "")

        if verify_pin(entered, stored_hash):
            # Success
            self.status_label.configure(text="[SUCCESS] Access Granted. Unlocking...", text_color="#22c55e")
            self.update()
            self.after(500, self.destroy)
        else:
            # Failed attempt
            self.failed_count += 1
            remaining = max(0, self.attempts_limit - self.failed_count)
            self.pin_entry.delete(0, "end")

            if self.failed_count >= self.attempts_limit:
                # 3 STRIKES BREACH TRIGGERED!
                self.center_frame.configure(border_color="#ef4444")
                self.status_label.configure(
                    text="[BREACH!] 3 FAILED ATTEMPTS - LOCKING & CAPTURING!",
                    text_color="#ef4444"
                )
                self.title_label.configure(text="SECURITY BREACH DETECTED!", text_color="#ef4444")
                self.unlock_btn.configure(state="disabled", fg_color="#7f1d1d")
                self.update()

                # Execute Case 1 response
                self.monitor.execute_case_1_lockout(
                    reason="3 FAILED SYSTEM PASSWORD ATTEMPTS ON LOCK SHIELD"
                )
                self.after(2000, self.destroy)
            else:
                self.status_label.configure(
                    text=f"[INCORRECT] Warning: {remaining} attempt(s) remaining!",
                    text_color="#f59e0b"
                )


if __name__ == "__main__":
    app = LockShieldApp()
    app.mainloop()
