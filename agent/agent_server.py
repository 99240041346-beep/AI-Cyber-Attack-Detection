from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import subprocess
import shutil
import platform
import re
from typing import Any


app = FastAPI(
    title="Smart Cyber Forensic ADB Agent",
    version="1.0.0"
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# ADB HELPERS
# ---------------------------------------------------------

def adb_path() -> str | None:
    """
    Find adb.exe from PATH.
    """

    return shutil.which("adb")


def run_adb(
    args: list[str],
    timeout: int = 15
) -> tuple[bool, str]:

    adb = adb_path()

    if not adb:
        return False, "ADB executable was not found in PATH."

    try:

        result = subprocess.run(
            [adb] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=(
                subprocess.CREATE_NO_WINDOW
                if platform.system() == "Windows"
                else 0
            )
        )

        output = (
            result.stdout.strip()
            if result.stdout
            else result.stderr.strip()
        )

        return (
            result.returncode == 0,
            output
        )

    except subprocess.TimeoutExpired:

        return False, "ADB command timed out."

    except Exception as exc:

        return False, str(exc)


# ---------------------------------------------------------
# DEVICE LIST
# ---------------------------------------------------------

def get_devices() -> list[dict[str, Any]]:

    success, output = run_adb(
        ["devices", "-l"]
    )

    if not success:
        return []

    devices = []

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith("list of devices"):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        serial = parts[0]
        state = parts[1]

        device = {
            "serial": serial,
            "state": state,
            "manufacturer": "",
            "model": "",
            "android": "",
            "android_version": "",
        }

        for item in parts[2:]:

            if ":" not in item:
                continue

            key, value = item.split(
                ":",
                1
            )

            value = value.replace(
                "_",
                " "
            )

            if key == "product":
                device["product"] = value

            elif key == "model":
                device["model"] = value

            elif key == "device":
                device["device"] = value

            elif key == "transport_id":
                device["transport_id"] = value

        devices.append(device)

    return devices


# ---------------------------------------------------------
# DEVICE PROPERTIES
# ---------------------------------------------------------

def get_device_properties(
    serial: str
) -> dict[str, str]:

    properties = {}

    commands = {
        "manufacturer": "ro.product.manufacturer",
        "model": "ro.product.model",
        "android": "ro.build.version.release",
        "android_version": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "security_patch": "ro.build.version.security_patch",
    }

    for name, prop in commands.items():

        success, output = run_adb(
            [
                "-s",
                serial,
                "shell",
                "getprop",
                prop
            ]
        )

        if success:

            properties[name] = output.strip()

    return properties


# ---------------------------------------------------------
# ADB STATUS
# ---------------------------------------------------------

@app.get("/")
def root():

    return {
        "service": "Smart Cyber Forensic ADB Agent",
        "status": "online",
        "adb_available": adb_path() is not None
    }


@app.get("/health")
def health():

    return {
        "status": "ok",
        "adb_available": adb_path() is not None
    }


@app.get("/api/adb/status")
def adb_status():

    adb = adb_path()

    if not adb:

        return JSONResponse(
            status_code=200,
            content={
                "adb_available": False,
                "agent_online": True,
                "devices": [],
                "connected_devices": 0,
                "authorized_devices": 0,
                "unauthorized_devices": 0,
                "error": (
                    "ADB was not found. "
                    "Make sure Android platform-tools "
                    "is installed and adb is available in PATH."
                )
            }
        )

    devices = get_devices()

    authorized = [
        device
        for device in devices
        if device.get("state") == "device"
    ]

    unauthorized = [
        device
        for device in devices
        if device.get("state") == "unauthorized"
    ]

    offline = [
        device
        for device in devices
        if device.get("state") == "offline"
    ]

    primary_device = None

    if authorized:

        primary_device = authorized[0]

        serial = primary_device["serial"]

        properties = get_device_properties(
            serial
        )

        primary_device.update(
            properties
        )

    elif devices:

        primary_device = devices[0]

    return {
        "agent_online": True,
        "adb_available": True,

        "devices": devices,

        "connected_devices": len(
            devices
        ),

        "authorized_devices": len(
            authorized
        ),

        "unauthorized_devices": len(
            unauthorized
        ),

        "offline_devices": len(
            offline
        ),

        "device": primary_device,

        "error": None
    }


# ---------------------------------------------------------
# SCAN HELPERS
# ---------------------------------------------------------

def shell(
    serial: str,
    command: str,
    timeout: int = 20
) -> str:

    success, output = run_adb(
        [
            "-s",
            serial,
            "shell",
            command
        ],
        timeout=timeout
    )

    if success:
        return output

    return ""


def count_lines(text: str) -> int:

    if not text:
        return 0

    return len(
        [
            line
            for line in text.splitlines()
            if line.strip()
        ]
    )


# ---------------------------------------------------------
# FORENSIC SCAN
# ---------------------------------------------------------

@app.post("/api/adb/scan")
def adb_scan():

    devices = get_devices()

    authorized = [
        d for d in devices
        if d.get("state") == "device"
    ]

    if not authorized:

        return JSONResponse(
            status_code=400,
            content={
                "error":
                    "No authorized Android device detected."
            }
        )

    device = authorized[0]

    serial = device["serial"]

    properties = get_device_properties(
        serial
    )

    # -----------------------------------------------------
    # Installed applications
    # -----------------------------------------------------

    packages = shell(
        serial,
        "pm list packages",
        timeout=30
    )

    applications = count_lines(
        packages
    )

    # -----------------------------------------------------
    # Running processes
    # -----------------------------------------------------

    processes = shell(
        serial,
        "ps -A",
        timeout=30
    )

    running_processes = count_lines(
        processes
    )

    # -----------------------------------------------------
    # Contacts
    #
    # Access depends on Android version, permissions,
    # OEM restrictions and whether the connected device
    # exposes the provider through the current ADB shell.
    # -----------------------------------------------------

    contacts_output = shell(
        serial,
        (
            "content query "
            "--uri content://contacts/phones "
            "--projection display_name:number"
        ),
        timeout=30
    )

    contacts = count_lines(
        contacts_output
    )

    # -----------------------------------------------------
    # SMS
    # -----------------------------------------------------

    sms_output = shell(
        serial,
        (
            "content query "
            "--uri content://sms "
            "--projection _id:address:date:body"
        ),
        timeout=30
    )

    sms = count_lines(
        sms_output
    )

    # -----------------------------------------------------
    # Basic suspicious-package keyword analysis
    #
    # This is a heuristic indicator, not a malware verdict.
    # -----------------------------------------------------

    suspicious_keywords = [
        "frida",
        "xposed",
        "magisk",
        "supersu",
        "busybox",
        "metasploit",
        "burp",
        "mitm",
        "packet",
        "inject",
        "spy"
    ]

    suspicious_matches = []

    package_lines = packages.splitlines()

    for package_line in package_lines:

        lower = package_line.lower()

        for keyword in suspicious_keywords:

            if keyword in lower:

                suspicious_matches.append(
                    {
                        "package": package_line,
                        "indicator": keyword
                    }
                )

                break

    # -----------------------------------------------------
    # Return scan result
    # -----------------------------------------------------

    return {
        "success": True,

        "serial": serial,

        "manufacturer":
            properties.get(
                "manufacturer",
                ""
            ),

        "model":
            properties.get(
                "model",
                ""
            ),

        "android":
            properties.get(
                "android",
                ""
            ),

        "android_version":
            properties.get(
                "android_version",
                ""
            ),

        "sdk":
            properties.get(
                "sdk",
                ""
            ),

        "security_patch":
            properties.get(
                "security_patch",
                ""
            ),

        "contacts": contacts,

        "sms": sms,

        "applications": applications,

        "running": running_processes,

        "suspicious":
            len(suspicious_matches),

        "suspicious_packages":
            suspicious_matches
    }


# ---------------------------------------------------------
# START SERVER
# ---------------------------------------------------------

if __name__ == "__main__":

    import uvicorn

    print()
    print("=" * 60)
    print(" SMART CYBER FORENSIC ADB AGENT")
    print("=" * 60)

    print(
        f"ADB executable: {adb_path()}"
    )

    devices = get_devices()

    print(
        f"ADB devices detected: {len(devices)}"
    )

    for device in devices:

        print(
            f"  {device.get('serial')} "
            f"[{device.get('state')}]"
        )

    print()
    print(
        "Agent URL: http://127.0.0.1:8765"
    )

    print("=" * 60)
    print()

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8765
    )
