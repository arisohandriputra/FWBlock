<p align="center">
  <img src="res/app.ico" width="80" height="80" alt="FWBlock Icon"/>
</p>

<h1 align="center">FWBlock</h1>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-blue?logo=windows&logoColor=white" alt="Platform"/>
  <img src="https://img.shields.io/badge/language-C%2B%2B-00599C?logo=c%2B%2B&logoColor=white" alt="Language"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License"/>
  <img src="https://img.shields.io/badge/build-Visual%20Studio%202010-purple?logo=visualstudio&logoColor=white" alt="Build"/>
  <img src="https://img.shields.io/badge/release-v3.0-orange" alt="Release"/>
</p>

<p align="center">
  A lightweight utility to block applications from internet access or execution — with scheduled blocking, password protection, system tray, and auto-start on boot. No installation required.
</p>

<p align="center">
  <a href="https://github.com/sponsors/arisohandriputra">
    <img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white" alt="Sponsor"/>
  </a>
</p>

---

## Features

- **Block Firewall** — Creates inbound & outbound Windows Firewall rules to cut off an application's network access
- **Block Running** — Prevents an application from launching at all using the Image File Execution Options (IFEO) registry method
- **Block Both** — Applies both methods simultaneously in a single click
- **Unblock** — Removes all blocking rules for a selected application
- **Scheduled Blocking** — Set a precise start and end date/time (with seconds, e.g. `15:22:00`) for any block — executes automatically even if FWBlock is closed, via Windows Task Scheduler
- **Realtime Scheduler** — In-app timer checks every second for exact on-time execution
- **Password Protection** — Optionally lock any block entry with a password; required before unblocking
- **Start with Windows** — Optional autostart: FWBlock silently runs in the system tray on every boot and re-applies all saved blocks automatically
- **System Tray** — Minimizes to tray instead of closing; right-click for quick access
- **Persistent Data** — All blocked entries and schedules are saved and fully restored after reboot
- **Single EXE** — No installation, no external dependencies — copy `FWBlock.exe` anywhere and run

---

## Requirements

| Component | Details |
|---|---|
| OS | Windows XP SP2 or later |
| Privileges | Administrator (UAC prompt appears automatically) |
| Runtime | None required (statically linked) |
| Windows Firewall | Service must be running for firewall features |

---

## Usage

### Manual Blocking

1. Run `FWBlock.exe` — UAC will automatically request Administrator privileges
2. Click **Browse** to select the `.exe` file you want to block
3. Choose a blocking method:
   - **Block Firewall** → block network access only
   - **Block Running** → prevent the application from launching
   - **Block Both** → apply both methods at once
4. Optionally set a password to protect the entry from being unblocked without it
5. The blocked application appears in the list
6. Select an item and click **Unblock Selected** to remove the block

### Scheduled Blocking

1. Click **Schedule** to open the schedule dialog
2. Browse and select the target `.exe`
3. Set **Start** date & time (e.g. `2026-05-15 15:22:00`) and optionally an **End** date & time
4. Choose block type and optional password, then click **OK**
5. FWBlock registers a Windows Task Scheduler entry — the block will fire even if FWBlock is not running at the time

> **Tip:** If the scheduled end time is reached while FWBlock is running, the entry is automatically unblocked and removed from the list.

### Start with Windows (Silent Autostart)

- Go to **Tools → Start with Windows** or right-click the tray icon → **Start with Windows** to toggle
- A checkmark indicates the feature is active
- When enabled, FWBlock launches silently on every boot (hidden in tray), re-applies all saved blocks, and watches for scheduled events — no window appears until you open it from the tray

---

## Building from Source

**Requirements:**
- Visual Studio 2010 or later
- Windows SDK

**Steps:**
```
1. Open FirewallBlocker.vcxproj in Visual Studio
2. Select the Release | Win32 configuration
3. Build → Build Solution (Ctrl+Shift+B)
4. Output: Release\FWBlock.exe
```

---

## Technology

| Component | Details |
|---|---|
| Language | C++ (native Win32) |
| GUI | Win32 API dialog-based |
| Firewall API | `INetFwPolicy2` (COM) |
| Process Block | Image File Execution Options (IFEO) registry |
| Scheduler | Windows Task Scheduler (`schtasks`) + in-app 1-second timer |
| Autostart | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Storage | `%APPDATA%\FWBlock\` (blocked list + schedule list) |
| Runtime | Statically linked — no MSVCR DLL dependency |

---

## Project Structure

```
FWBlock/
├── FirewallBlocker.cpp     # Main source file
├── FirewallBlocker.h       # Header & declarations
├── FirewallBlocker.rc      # Resources (dialogs, menus, icons, version info)
├── FirewallBlocker.vcxproj # Visual Studio project file
├── resource.h              # Resource ID definitions
└── res/
    ├── app.ico             # Application icon
    ├── small.ico           # Small icon
    └── btn_*.ico           # Button icons
```

---

## Scheduled Block Flow

```
User sets schedule
       │
       ├─ FWBlock registers Windows Task (start + end)
       │
       ▼
  Start time reached
  (via Task Scheduler or in-app 1s timer)
       │
       └─ Block applied → status: Active
              │
              ▼
         End time reached
         (via Task Scheduler or in-app 1s timer)
              │
              └─ Block removed → entry deleted from list
```

---

## Notes

- **Block Running** modifies `HKEY_LOCAL_MACHINE` — Administrator privileges are required
- The **Windows Firewall service** must be running for firewall blocking to work
- Closing the window minimizes to tray — use **Exit** from the tray menu to fully quit
- **Start with Windows** stores a registry value under `HKCU\...\Run`; removing the checkmark deletes it
- FWBlock does not collect, store, or transmit any data outside your local machine

---

## Sponsor

If you find FWBlock useful, consider supporting the development:

[![Sponsor](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/arisohandriputra)

---

## Author

**Ari Sohandri Putra**  
[github.com/arisohandriputra/FWBlock](https://github.com/arisohandriputra/FWBlock)

---
