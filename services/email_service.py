"""
Aegis Sentinel - Email Alert Service
Transmits forensic breach reports and 5-burst intruder photos to designated Gmail
using secure SSL/TLS SMTP and responsive HTML formatting.
"""

import os
import socket
import smtplib
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from typing import List, Optional


class EmailService:
    """Dispatches intruder alerts with embedded photos and location coordinates."""

    @staticmethod
    def send_breach_alert(
        config: dict,
        location: dict,
        image_paths: List[Path],
        alert_reason: str = "3 FAILED PASSWORD ATTEMPTS"
    ) -> bool:
        """
        Send comprehensive forensic security email via Gmail SMTP.
        Attaches all captured images and includes live Google Maps link.
        """
        sender = config.get("gmail_sender", "").strip()
        app_password = config.get("gmail_app_password", "").strip()
        receiver = config.get("gmail_receiver", "").strip()
        smtp_server = config.get("smtp_server", "smtp.gmail.com")
        smtp_port = int(config.get("smtp_port", 465))

        if not sender or not app_password or not receiver:
            print("[EmailService] [WARNING] Gmail credentials not fully configured in settings.")
            return False

        lat = location.get("lat")
        lon = location.get("lon")
        city = location.get("city", "Unknown")
        region = location.get("region", "Unknown")
        country = location.get("country", "Unknown")
        ip = location.get("ip", "Unknown")
        isp = location.get("isp", "Unknown")
        status = location.get("status", "LIVE")
        maps_url = location.get("maps_url") or ""
        coordinates = f"{lat:.6f}, {lon:.6f} (approximate IP estimate)" if lat is not None and lon is not None else "Unavailable"
        hostname = socket.gethostname()

        subject = f"[AEGIS ALERT] CRITICAL: System Security Breach - {hostname}"

        # Build HTML Email Body
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 20px; }}
            .card {{ background-color: #1a2234; border: 1px solid #ef4444; border-radius: 10px; max-width: 650px; margin: 0 auto; overflow: hidden; }}
            .header {{ background-color: #dc2626; color: #ffffff; padding: 18px 24px; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 22px; letter-spacing: 1px; }}
            .content {{ padding: 24px; }}
            .badge {{ background-color: #991b1b; color: #fecaca; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px; }}
            .table-box {{ width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 20px; }}
            .table-box td {{ padding: 8px 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
            .table-box td.label {{ color: #94a3b8; font-weight: bold; width: 35%; }}
            .btn {{ display: inline-block; background-color: #2563eb; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; margin-top: 10px; }}
            .footer {{ background-color: #0f172a; padding: 12px 24px; text-align: center; font-size: 12px; color: #64748b; }}
          </style>
        </head>
        <body>
          <div class="card">
            <div class="header">
              <h1>AEGIS SECURITY BREACH REPORT</h1>
            </div>
            <div class="content">
              <p><span class="badge">INCIDENT DETECTED</span></p>
              <p>The system defense monitor on <strong>{hostname}</strong> has intercepted an unauthorized intrusion:</p>
              
              <table class="table-box">
                <tr><td class="label">Incident Reason:</td><td style="color: #f87171; font-weight: bold;">{alert_reason}</td></tr>
                <tr><td class="label">System Action:</td><td>Workstation Locked & Burst Camera Engaged</td></tr>
                <tr><td class="label">Network area estimate:</td><td>{city}, {region} ({country})</td></tr>
                <tr><td class="label">Approximate coordinates:</td><td>{coordinates}</td></tr>
                <tr><td class="label">IP Address:</td><td>{ip}</td></tr>
                <tr><td class="label">ISP Provider:</td><td>{isp}</td></tr>
                <tr><td class="label">Location Mode:</td><td>{status}</td></tr>
                <tr><td class="label">Forensic Photos:</td><td>{len(image_paths)} frames captured and attached</td></tr>
              </table>

              <p style="text-align: center;">
                {f'<a href="{maps_url}" class="btn" target="_blank">View Approximate Area On Google Maps</a>' if maps_url else '<span>Map unavailable</span>'}
              </p>
              
              <p style="font-size: 13px; color: #94a3b8; margin-top: 25px;">
                IP location is an estimate and is not GPS-accurate. Camera capture depends on device permissions and availability.
              </p>
            </div>
            <div class="footer">
              Aegis Sentinel Autonomous Host Defense &bull; Generated automatically
            </div>
          </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("related")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = receiver

        part_html = MIMEText(html_content, "html")
        msg.attach(part_html)

        # Attach all captured burst images
        for img_path in image_paths:
            if img_path.exists():
                try:
                    with open(img_path, "rb") as f:
                        img_data = f.read()
                        mime_img = MIMEImage(img_data)
                        mime_img.add_header("Content-Disposition", "attachment", filename=img_path.name)
                        msg.attach(mime_img)
                except Exception as e:
                    print(f"[EmailService] Could not attach {img_path.name}: {e}")

        # Send via SMTP
        try:
            print(f"[EmailService] Connecting to {smtp_server}:{smtp_port} for alert delivery...")
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=12)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=12)
                server.starttls()

            server.login(sender, app_password)
            server.sendmail(sender, [receiver], msg.as_string())
            server.quit()
            print(f"[EmailService] [SUCCESS] Breach alert sent to {receiver} with {len(image_paths)} images.")
            return True
        except Exception as e:
            print(f"[EmailService] [ERROR] Email delivery failed: {e}")
            return False
