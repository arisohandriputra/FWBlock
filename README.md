# 🔒 FWBlock

**FWBlock** is a lightweight native Windows desktop utility that lets you block applications from accessing the internet or running entirely - all through a simple graphical interface, without manually touching Windows Firewall settings.

---

## ✨ Features

- **Block Firewall** — Creates inbound & outbound Windows Firewall rules to cut off an application's network access
- **Block Running** — Prevents an application from launching at all using the Image File Execution Options (IFEO) registry method
- **Block Both** — Applies both methods simultaneously in a single click
- **Unblock** — Removes all blocking rules for a selected application
- **Persistent List** — Blocked applications are saved automatically and restored on next launch
- **Single EXE** — No installation required, no external dependencies

---

## 🖥️ Requirements

| Component | Details |
|---|---|
| OS | Windows XP SP2 or later |
| Privileges | Administrator (UAC prompt appears automatically) |
| Runtime | None required (statically linked) |
| Windows Firewall | Service must be running for firewall features |

---

## 🚀 Usage

1. Run `FirewallBlocker.exe` — UAC will automatically request Administrator privileges
2. Click **Browse** to select the `.exe` file you want to block
3. Choose a blocking method:
   - **Block Firewall** → block network access only
   - **Block Running** → prevent the application from launching
   - **Block Both** → apply both methods at once
4. The blocked application will appear in the list
5. Select an item from the list and click **Unblock Selected** to remove the block

---

## 🔧 Building from Source

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

## 🛠️ Technology

| Component | Details |
|---|---|
| Language | C++ (native Win32) |
| GUI | Win32 API dialog-based |
| Firewall API | `INetFwPolicy2` (COM) |
| Process Block | Image File Execution Options (IFEO) registry |
| Storage | `%APPDATA%\FirewallBlocker\blocked_list.dat` |
| Runtime | Statically linked — no MSVCR DLL dependency |

---

## 📁 Project Structure

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

## ⚠️ Notes

- **Block Running** modifies `HKEY_LOCAL_MACHINE` registry — Administrator privileges are required
- The **Windows Firewall service** must be running for firewall blocking to work
- FWBlock does not collect, store, or transmit any data outside of your local machine

---

## 👤 Author

**Ari Sohandri Putra**
[github.com/arisohandriputra/FWBlock](https://github.com/arisohandriputra/FWBlock)

---

## 📄 License

This project is open source. Feel free to use, modify, and distribute.
