<p align="center">
  <img src="res/app.ico" width="80" height="80" alt="FWBlock Icon"/>
</p>

<h1 align="center">FWBlock</h1>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-blue?logo=windows&logoColor=white" alt="Platform"/>
  <img src="https://img.shields.io/badge/language-C%2B%2B-00599C?logo=c%2B%2B&logoColor=white" alt="Language"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License"/>
  <img src="https://img.shields.io/badge/build-Visual%20Studio%202010-purple?logo=visualstudio&logoColor=white" alt="Build"/>
  <img src="https://img.shields.io/badge/release-v1.0-orange" alt="Release"/>
</p>

<p align="center">
  A lightweight utility to block applications from internet access or execution - no installation required.
</p>

<p align="center">
  <a href="https://github.com/sponsors/arisohandriputra">
    <img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white" alt="Sponsor"/>
  </a>
</p>

---

## Features

- **Block Firewall** - Creates inbound & outbound Windows Firewall rules to cut off an application's network access
- **Block Running** - Prevents an application from launching at all using the Image File Execution Options (IFEO) registry method
- **Block Both** - Applies both methods simultaneously in a single click
- **Unblock** - Removes all blocking rules for a selected application
- **Persistent List** - Blocked applications are saved automatically and restored on next launch
- **Single EXE** - No installation required, no external dependencies

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

1. Run `FirewallBlocker.exe` - UAC will automatically request Administrator privileges
2. Click **Browse** to select the `.exe` file you want to block
3. Choose a blocking method:
   - **Block Firewall** > block network access only
   - **Block Running** > prevent the application from launching
   - **Block Both** > apply both methods at once
4. The blocked application will appear in the list
5. Select an item from the list and click **Unblock Selected** to remove the block

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
| Storage | `%APPDATA%\FirewallBlocker\blocked_list.dat` |
| Runtime | Statically linked - no MSVCR DLL dependency |

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

## Notes

- **Block Running** modifies `HKEY_LOCAL_MACHINE` registry - Administrator privileges are required
- The **Windows Firewall service** must be running for firewall blocking to work
- FWBlock does not collect, store, or transmit any data outside of your local machine

---

## Sponsor

If you find FWBlock useful, consider supporting the development:

[![Sponsor](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-ea4aaa?logo=github-sponsors&logoColor=white)](https://github.com/sponsors/arisohandriputra)

---

## Author

**Ari Sohandri Putra**
[github.com/arisohandriputra/FWBlock](https://github.com/arisohandriputra/FWBlock)

---
