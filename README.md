# Smart Cyber Forensic Pro

Full Render-ready Android forensic triage web application.

## Render
Build command:
`pip install --upgrade pip && pip install -r requirements.txt`

Start command:
`uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

Python:
`3.13.5`

Set `CASE_API_KEY` in Render. `render.yaml` can generate it.

## Local ADB agent
Install Android Platform Tools and Python 3.10+.

Windows:
```bat
set FORENSIC_SERVER=https://YOUR-SERVICE.onrender.com
set CASE_API_KEY=YOUR_RENDER_KEY
python -m pip install -r agent/requirements.txt
python agent/agent.py
```

The phone must be physically connected to the analyst computer with USB debugging authorized.

## Features
3D login, dashboard, ADB acquisition reference, device/security properties, contacts and SMS counts/details, application inventory, running-process snapshot, accessibility services, device-admin indicators, network snapshot, APK SHA-256 hashes, suspicious package heuristics, case history, detail views and JSON export.

Android access depends on device/OEM/API/permissions. No exploit, stealth persistence, automatic deletion, or security bypass is included.
