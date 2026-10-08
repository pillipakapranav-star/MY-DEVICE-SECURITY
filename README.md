# VANDY — Aegis Sentinel

VANDY is a local Windows security-learning project. This upgrade keeps the original desktop dashboard, PIN shield, face enrollment, camera capture, incident history, Windows workstation lock, and optional email/SMS alerts.

## What it does

- The desktop dashboard and optional lock shield check the VANDY Master PIN. Repeated failed attempts can run the configured response.
- Owner Sentry can use the webcam and locally enrolled face model to flag faces it does not recognize.
- A response can ask Windows to lock the logged-in workstation, capture camera images, record an incident, and send alerts when you have configured those features.
- PINs are stored as salted PBKDF2 hashes. A legacy SHA-256 PIN is accepted once and upgraded after successful verification.
- Location results are labelled correctly: this project uses an internet IP lookup, which estimates a network area. It does not read device GPS and cannot promise an exact device location. A saved estimate is labelled stale, never current.

## Important limits

This is a learning prototype. The dashboard and shield protect VANDY after you launch it; they do not replace or secure Windows before your account signs in. The Windows Event ID 4625 monitor is present in the code but is not started by the application. Face recognition can misidentify people and is not a substitute for Windows Hello or another operating-system authentication method. Windows lock, camera access, SMS hardware, email delivery, internet lookup, and recognition each depend on permissions, drivers, connectivity, and configuration. Mail and SMS credentials are saved in the local configuration file; keep that file private.

The clean starter configuration retains the original demo PIN `1234`. Change it to a unique PIN with at least 8 characters in **Settings** before using the shield. Do not use this prototype as your only protection for a real device.

## Run on Windows

1. Install Python 3.10 or newer and allow the Python installer to add Python to PATH.
2. Open this folder in Antigravity or a terminal.
3. In the project terminal, install the listed packages:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. Start the dashboard:

   ```powershell
   py main.py
   ```

   Or double-click `run_aegis.bat`.

5. Change the demo PIN under **Settings**. Enroll your own face if you want to use Owner Sentry. The face samples and model will be saved locally under `data/owner_faces/` and `data/`.
6. Set up optional email and SMS details in the dashboard. Never share app passwords or API tokens. Email and SMS are off in the clean starter configuration.

## Folder map

```text
VANDY_AegisSentinel/
├── main.py                       # Dashboard launcher and CLI
├── lock_shield.py                # VANDY PIN shield
├── config.py                     # Settings and PIN hashing
├── services/                     # Camera, face, location, lock, alerts
├── ui/main_window.py             # Desktop dashboard
├── data/                          # Local configuration and face enrollment
├── captured_intruders/            # Local incident photos
├── requirements.txt
├── run_aegis.bat
└── run_cli_menu.bat
```

`data/` and `captured_intruders/` are clean on first run. They will contain device-specific data after you use the app; keep them private and remove them before sharing the project.

## Develop it yourself

Start in `services/security_monitor.py` to understand the response flow. Then inspect the smaller service modules, and use `ui/main_window.py` to see how buttons connect to them. `services/location_service.py` is intentionally explicit about IP location being approximate. Make one change at a time and review the permissions and external effects before enabling camera capture, workstation lock, or message dispatch.
