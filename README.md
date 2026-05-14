<div align="center">

<img src="res/app.ico" width="80" height="80" alt="FWBlock Icon" />

# FWBlock  FirewallBlocker

**A lightweight native Win32 utility to block applications from internet access and/or execution on Windows.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078d7.svg?logo=windows)](https://github.com/arisohandriputra/FWBlock)
[![Language: C++](https://img.shields.io/badge/Language-C%2B%2B-00599C.svg?logo=c%2B%2B)](https://github.com/arisohandriputra/FWBlock)
[![Build: MSVC](https://img.shields.io/badge/Build-MSVC%20%2F%20Visual%20Studio-5C2D91.svg?logo=visualstudio)](https://github.com/arisohandriputra/FWBlock)

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/arisohandriputra)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Building from Source](#building-from-source)
- [Usage](#usage)
- [Architecture & Code Walkthrough](#architecture--code-walkthrough)
  - [Project Structure](#project-structure)
  - [Core Data Structure](#core-data-structure)
  - [Block Type Flags](#block-type-flags)
  - [Firewall Management](#firewall-management-inetfwpolicy2)
  - [Process Execution Blocking (IFEO)](#process-execution-blocking-ifeo)
  - [Persistent Storage](#persistent-storage)
  - [UAC Auto-Elevation](#uac-auto-elevation)
  - [Win32 GUI Layer](#win32-gui-layer)
- [Development Guide](#development-guide)
  - [Setting Up the Environment](#setting-up-the-environment)
  - [Adding a New Blocking Method](#adding-a-new-blocking-method)
  - [Extending the UI](#extending-the-ui)
  - [Adding Persistence Fields](#adding-persistence-fields)
  - [Coding Conventions](#coding-conventions)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**FWBlock** (FirewallBlocker) is a compact, dependency-free Windows desktop application written in pure C++ with the Win32 API. It allows users to:

- Create and remove **Windows Firewall rules** (inbound + outbound) for any executable.
- Prevent applications from **launching entirely** via the Windows Image File Execution Options (IFEO) registry mechanism.
- Apply **both restrictions simultaneously** with a single action.
- Manage a **persistent blocked list** that survives reboots and application restarts.

FWBlock is designed for system administrators, power users, and developers who need fine-grained control over which applications may communicate over the network or run at all - without the overhead of third-party security suites.

---

## Features

| Feature | Description |
|---|---|
| **Firewall Blocking** | Adds inbound + outbound Windows Firewall rules via `INetFwPolicy2` COM API |
| **Process Blocking** | Prevents execution using the IFEO (Image File Execution Options) debugger trick |
| **Combined Mode** | Applies both firewall and process restrictions simultaneously |
| **Smart Toggle** | Buttons dynamically switch between Block / Unblock based on current state |
| **Persistent List** | Blocked entries are saved to `%APPDATA%\FirewallBlocker\blocked_list.dat` |
| **Auto-Elevation** | Automatically relaunches with Administrator privileges via UAC `runas` |
| **Native Win32 UI** | No .NET, no MFC, no external frameworks - pure Win32 dialog with ListView |
| **Lightweight** | Minimal resource footprint; compatible with Windows XP SP3 and later |

---

## Screenshots

<img width="587" height="531" alt="image" src="https://github.com/user-attachments/assets/bac97472-a127-4cf8-a4b8-aae784582861" />

---

## Requirements

| Component | Minimum Version |
|---|---|
| **OS** | Windows XP SP3 / Windows Vista or later (tested on Win 10/11) |
| **Compiler** | MSVC (Visual Studio 2010 or later) |
| **SDK** | Windows SDK with `netfw.h`, `comdef.h`, `atlbase.h` |
| **Privileges** | Administrator (required for firewall and registry operations) |

**Linked libraries** (via `#pragma comment`):

```
comctl32.lib  comdlg32.lib  shell32.lib
ole32.lib     oleaut32.lib  advapi32.lib
```

---

## Building from Source

1. **Clone the repository**

   ```bash
   git clone https://github.com/arisohandriputra/FWBlock.git
   cd FWBlock
   ```

2. **Open the solution in Visual Studio**

   Open `FirewallBlocker.vcxproj` (or its parent `.sln` if present) in Visual Studio 2010 or later.

3. **Select a build configuration**

   | Configuration | Output | Runtime |
   |---|---|---|
   | `Debug \| Win32` | `Debug\FirewallBlocker.exe` | `MultiThreadedDebugDLL` |
   | `Release \| Win32` | `Release\FirewallBlocker.exe` | `MultiThreadedDLL` |

4. **Build**

   Press `Ctrl+Shift+B` or go to **Build → Build Solution**.

5. **Run as Administrator**

   The application auto-elevates on first launch via UAC if not already elevated.

> **Note:** The project targets `_WIN32_WINNT 0x0501` (Windows XP SP3+) for maximum compatibility. If you target Windows Vista or later only, you may raise this value to unlock additional APIs.

---

## Usage

1. Launch `FirewallBlocker.exe` (UAC prompt will appear if not running as Administrator).
2. Use **Browse** to select any `.exe` file, or type a path directly into the path field.
3. Choose a blocking action:
   - **Block Firewall** - denies inbound + outbound network access.
   - **Block Running** - prevents the application from launching (IFEO).
   - **Block Both** - applies both restrictions at once.
4. The entry appears in the blocked list with its current status.
5. **Select any entry** in the list - the buttons update to reflect its current state (Block / Unblock).
6. Use **Unblock** to fully remove all restrictions for a selected entry.
7. Use **Refresh** to re-sync the displayed states against the live Windows Firewall and registry.

All changes persist automatically to `%APPDATA%\FirewallBlocker\blocked_list.dat`.

---

## Architecture & Code Walkthrough

### Project Structure

```
FWBlock/
├── FirewallBlocker.cpp      # All application logic and Win32 message handling
├── FirewallBlocker.h        # Declarations, structs, constants, function prototypes
├── FirewallBlocker.rc       # Win32 resource script (dialogs, menus, icons)
├── FirewallBlocker.vcxproj  # Visual Studio project file
├── resource.h               # Resource ID definitions (IDC_*, IDI_*, IDR_*, IDD_*)
└── res/
    ├── app.ico              # Application icon (large)
    └── small.ico            # Application icon (small / taskbar)
```

### Core Data Structure

`BlockedEntry` (defined in `FirewallBlocker.h`) is the central record type that tracks every managed application:

```cpp
struct BlockedEntry {
    std::wstring filePath;    // Full absolute path to the executable
    std::wstring fileName;    // Basename (e.g., "chrome.exe")
    std::wstring ruleName;    // Auto-generated rule name prefix ("FWB_chrome.exe")
    int          blockType;   // Bitmask: BLOCK_FIREWALL | BLOCK_PROCESS | BLOCK_BOTH
    bool         fwBlocked;   // True if Windows Firewall rule is active
    bool         procBlocked; // True if IFEO registry entry is present
};
```

A global `std::vector<BlockedEntry> g_blockedList` holds all entries in memory at runtime and is serialized to disk on every change.

### Block Type Flags

```cpp
#define BLOCK_FIREWALL  0x01   // Internet/network access denied
#define BLOCK_PROCESS   0x02   // Execution prevented via IFEO
#define BLOCK_BOTH      0x03   // Both restrictions applied
```

These bitmask values allow future extension (e.g., `0x04` for a hosts-file redirect) without breaking existing serialized data.

### Firewall Management (`INetFwPolicy2`)

**File:** `FirewallBlocker.cpp` - functions `AddFirewallRule`, `RemoveFirewallRule`, `IsFirewallRuleExists`

FWBlock communicates with the Windows Firewall engine through the COM interface `INetFwPolicy2`, instantiated via `CoCreateInstance`. For each blocked application, two rules are created:

| Rule | Direction | Name Pattern |
|---|---|---|
| Inbound block | `NET_FW_RULE_DIR_IN` | `FWB_<filename>_IN` |
| Outbound block | `NET_FW_RULE_DIR_OUT` | `FWB_<filename>_OUT` |

Both rules use `NET_FW_ACTION_BLOCK` and are applied across `NET_FW_PROFILE2_ALL` (Domain, Private, and Public profiles simultaneously).

```cpp
// Simplified rule creation pattern
CComPtr<INetFwPolicy2> pFwPolicy2;
CoCreateInstance(__uuidof(NetFwPolicy2), ..., (void**)&pFwPolicy2);

CComPtr<INetFwRule> pRule;
CoCreateInstance(__uuidof(NetFwRule), ..., (void**)&pRule);
pRule->put_Action(NET_FW_ACTION_BLOCK);
pRule->put_Direction(NET_FW_RULE_DIR_OUT);
pRule->put_Profiles(NET_FW_PROFILE2_ALL);

CComPtr<INetFwRules> pRules;
pFwPolicy2->get_Rules(&pRules);
pRules->Add(pRule);
```

`CComPtr<>` (ATL smart pointers) ensures automatic `Release()` on scope exit, preventing COM resource leaks.

### Process Execution Blocking (IFEO)

**File:** `FirewallBlocker.cpp` - functions `BlockProcessExecution`, `UnblockProcessExecution`, `IsProcessBlocked`

Windows' **Image File Execution Options** (IFEO) is a registry mechanism originally intended for attaching debuggers to processes at launch. FWBlock exploits this by assigning a non-existent "debugger" path, causing Windows to fail silently when attempting to launch the target:

**Registry path:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exeName>
  Debugger = "C:\BLOCKED_BY_FIREWALL_BLOCKER.exe"
```

**Block:**
```cpp
RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey, ..., &hKey);
RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (BYTE*)blocker, size);
```

**Unblock:**
```cpp
RegDeleteValueW(hKey, L"Debugger");
RegDeleteKeyW(HKEY_LOCAL_MACHINE, subKey);
```

> ⚠️ This technique requires `HKEY_LOCAL_MACHINE` write access, which mandates Administrator privileges.

### Persistent Storage

**File:** `FirewallBlocker.cpp` - functions `SaveList`, `LoadList`, `GetPersistPath`

The blocked list is serialized to a plain-text `.dat` file at:

```
%APPDATA%\FirewallBlocker\blocked_list.dat
```

Each entry is stored as a fixed 7-line block:

```
<filePath>
<fileName>
<ruleName>
<blockType (int)>
<fwBlocked (0|1)>
<procBlocked (0|1)>
---
```

`SaveList()` is called immediately after every add, toggle, or remove operation - ensuring the on-disk state always matches memory. `LoadList()` runs during `WM_INITDIALOG` to restore the previous session.

If `%APPDATA%` is unavailable, the application falls back to the same directory as the executable.

### UAC Auto-Elevation

**File:** `FirewallBlocker.cpp` - functions `IsElevated`, `RelaunchAsAdmin`

At startup (`wWinMain`), the application checks its token elevation status:

```cpp
if (!IsElevated()) {
    RelaunchAsAdmin();
    return 0;
}
```

`RelaunchAsAdmin()` uses `ShellExecuteExW` with the `runas` verb, which triggers the standard Windows UAC consent dialog. The original (non-elevated) process immediately exits.

If elevation is refused or unavailable, the application still runs but displays a warning in the status bar and some operations will fail silently.

### Win32 GUI Layer

The interface is built with a single modeless dialog (`IDD_FIREWALLBLOCKER_DIALOG`) and a modal About dialog (`IDD_ABOUTBOX`), managed entirely through `MainDlgProc` and `AboutDlgProc` callback procedures.

**Key UI components:**

| Control ID | Type | Purpose |
|---|---|---|
| `IDC_LIST_BLOCKED` | `ListView` | Displays all blocked entries (5 columns) |
| `IDC_EDIT_PATH` | `Edit` | Input field for target executable path |
| `IDC_BTN_BROWSE` | `Button` | Opens `GetOpenFileNameW` file picker |
| `IDC_BTN_BLOCK_FW` | `Button` | Toggle firewall block (context-sensitive label) |
| `IDC_BTN_BLOCK_RUN` | `Button` | Toggle process block (context-sensitive label) |
| `IDC_BTN_BLOCK_BOTH` | `Button` | Toggle both blocks simultaneously |
| `IDC_BTN_UNBLOCK` | `Button` | Fully unblock selected entry and remove from list |
| `IDC_BTN_REFRESH` | `Button` | Re-sync display with live system state |
| `IDC_STATIC_STATUS` | `Static` | Status bar message |

The `UpdateBlockButtonLabels()` function is called on every `LVN_ITEMCHANGED` notification to keep button labels synchronized with the selected entry's current block state.

---

## Development Guide

### Setting Up the Environment

1. Install **Visual Studio 2019** or later (the free Community edition is sufficient).
2. During installation, select the **Desktop development with C++** workload.
3. Ensure the **Windows SDK** is included (version 10.0.x or later recommended).
4. Clone the repository and open `FirewallBlocker.vcxproj`.

### Adding a New Blocking Method

FWBlock is structured to make adding new restriction mechanisms straightforward:

1. **Define a new flag** in `FirewallBlocker.h`:

   ```cpp
   #define BLOCK_HOSTS  0x04   // Hosts-file based blocking
   ```

2. **Implement the block/unblock functions**:

   ```cpp
   // In FirewallBlocker.cpp
   bool BlockViaHosts(const std::wstring& exePath, const std::wstring& ruleName);
   bool UnblockViaHosts(const std::wstring& exePath, const std::wstring& ruleName);
   ```

3. **Declare them** in `FirewallBlocker.h`.

4. **Add a UI button** in `FirewallBlocker.rc` with a new resource ID in `resource.h`.

5. **Wire it** in `MainDlgProc` under the `WM_COMMAND` handler, following the existing pattern in `TryToggleSelected()`.

6. **Update serialization** - the `blockType` bitmask is already stored as an integer, so no format change is needed. Add detection logic to `IsProcessBlocked`-equivalent for the new method.

### Extending the UI

All dialog layouts are defined in `FirewallBlocker.rc`. To add controls:

1. Add the control definition inside the relevant `DIALOG` or `DIALOGEX` block in the `.rc` file.
2. Assign a unique resource ID in `resource.h` (follow the existing `IDC_*` naming pattern).
3. Reference the new ID in `FirewallBlocker.cpp` using `GetDlgItem(hDlg, IDC_YOUR_NEW_ID)`.

For ListView columns, modify `SetupListView()` in `FirewallBlocker.cpp` and update `RefreshListView()` to populate the new column via `ListView_SetItemText`.

### Adding Persistence Fields

To persist a new field in `BlockedEntry`:

1. Add the field to the struct in `FirewallBlocker.h`.
2. Append a new line to the serialization block in `SaveList()`.
3. Add a corresponding `std::getline` / parse step in `LoadList()`.
4. Increment the logical block version in a comment so future maintainers understand the format history.

> **Compatibility note:** The current parser skips entries with an empty `filePath` but does not validate the number of fields per block. If you change the record format, add a version header line at the top of the file and branch in `LoadList()` accordingly.

### Coding Conventions

| Convention | Rule |
|---|---|
| **Character set** | Unicode (`wchar_t`, `std::wstring`, `W`-suffixed Win32 functions) throughout |
| **COM resources** | Use `CComPtr<>` smart pointers; never call `Release()` manually |
| **Error handling** | Check `HRESULT` with `SUCCEEDED()` / `FAILED()`; surface errors via `MessageBoxW` |
| **Registry access** | Always close `HKEY` handles with `RegCloseKey()` |
| **Memory** | Prefer stack allocation and STL containers; avoid raw `new` / `delete` |
| **Naming** | Global variables prefixed `g_`; handles prefixed `h`; boolean functions start with `Is` |
| **Status updates** | Use `SetStatus(hDlg, msg)` for all user-facing feedback |

---

## Security Considerations

- FWBlock requires and enforces **Administrator privileges**. Do not deploy it in contexts where privilege escalation is undesirable.
- The IFEO mechanism writes to `HKEY_LOCAL_MACHINE`. A compromised or malfunctioning FWBlock instance could inadvertently block legitimate system executables. Always verify the target path before blocking.
- The persisted `blocked_list.dat` is a plain-text file. It does not contain sensitive credentials, but manipulation of this file by a low-privilege user between sessions could affect which entries are restored. Consider restricting the `%APPDATA%\FirewallBlocker\` directory's ACL if deploying in a shared environment.
- Firewall rules created by FWBlock are named with the `FWB_` prefix and grouped under `FirewallBlocker`. They can be reviewed and removed manually via `wf.msc` (Windows Defender Firewall with Advanced Security) if the application is uninstalled without cleaning up.

---

## Contributing

Contributions are welcome. Please follow these steps:

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes, following the [Coding Conventions](#coding-conventions) above.
3. **Test** on at least Windows 10 with both Debug and Release builds.
4. Open a **Pull Request** with a clear description of what was changed and why.
5. For significant changes, please open an **Issue** first to discuss the proposed direction.

**Bug reports:** Please include your Windows version, whether you are running as Administrator, and a clear description of the observed vs. expected behavior.

---

## License

```
MIT License

Copyright (c) 2026 Ari Sohandri Putra

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

Made with ❤️ by [Ari Sohandri Putra](https://github.com/arisohandriputra)

**[⭐ Star this repo](https://github.com/arisohandriputra/FWBlock)** · **[🐛 Report a Bug](https://github.com/arisohandriputra/FWBlock/issues)** · **[💡 Request a Feature](https://github.com/arisohandriputra/FWBlock/issues)** · **[❤️ Sponsor](https://github.com/sponsors/arisohandriputra)**

</div>
