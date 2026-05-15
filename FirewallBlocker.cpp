// =============================================================================
//  FirewallBlocker.cpp
// =============================================================================
//
//  Main Source File for FirewallBlocker
//
//  Author      : Ari Sohandri Putra
//  Repository  : https://github.com/arisohandriputra/FWBlock
//
//  Description :
//  This source file contains the complete implementation of the
//  FirewallBlocker application, including the graphical user
//  interface, Windows Firewall integration, process execution
//  blocking system, persistent storage handling, and Win32
//  message processing.
//
//  FirewallBlocker is a native Win32 desktop utility developed
//  in C++ using Visual Studio 2010. The application allows users
//  to:
//
//      - Block applications from internet access
//      - Create inbound and outbound firewall rules
//      - Prevent applications from running
//      - Manage blocked applications through a GUI
//      - Store blocked entries persistently
//
//  Core Technologies Used :
//      - Win32 API
//      - Windows Firewall COM API (INetFwPolicy2)
//      - Windows Registry API
//      - COM / ATL Smart Pointers
//      - Common Controls API
//      - Shell API
//
// =============================================================================
//
//  Main System Components
//  -----------------------------------------------------------------------------
//
//  1. Firewall Management
//  ----------------------
//  The application uses the Windows Firewall COM interface
//  (`INetFwPolicy2`) to dynamically create and remove firewall
//  rules for executable files.
//
//  Features include:
//
//      - Inbound blocking
//      - Outbound blocking
//      - Rule existence checking
//      - Automatic rule naming
//
//  Each blocked application receives unique firewall rules
//  generated from the executable filename.
//
// =============================================================================
//
//  2. Process Execution Blocking
//  -----------------------------
//  FirewallBlocker supports process restriction using the
//  Windows Image File Execution Options (IFEO) registry method.
//
//  The application creates registry entries inside:
//
//      HKEY_LOCAL_MACHINE
//      \SOFTWARE\Microsoft\Windows NT
//      \CurrentVersion\Image File Execution Options
//
//  By assigning a fake debugger executable, Windows prevents
//  the targeted application from launching.
//
// =============================================================================
//
//  3. Persistent Storage System
//  ----------------------------
//  Blocked applications are automatically saved to a local
//  data file stored inside:
//
//      %APPDATA%\FirewallBlocker\blocked_list.dat
//
//  The application restores all entries automatically during
//  startup, allowing persistent management across sessions.
//
// =============================================================================
//
//  4. Administrator Privilege Handling
//  -----------------------------------
//  Since firewall and registry operations require elevated
//  privileges, FirewallBlocker automatically checks whether
//  it is running as Administrator.
//
//  If not elevated, the application relaunches itself using
//  the Windows UAC `runas` mechanism.
//
// =============================================================================
//
//  5. Native Win32 User Interface
//  ------------------------------
//  The graphical interface is fully built using the native
//  Win32 API without external frameworks such as .NET or MFC.
//
//  Main UI Features:
//
//      - ListView-based blocked list
//      - Dynamic block/unblock buttons
//      - Status messages
//      - File browsing dialog
//      - About dialog
//      - Menu integration
//
//  The interface is lightweight, fast, and compatible with
//  older Windows operating systems.
//
// =============================================================================
//
//  6. ListView Management
//  ----------------------
//  The ListView system displays all blocked applications,
//  including:
//
//      - File name
//      - Block type
//      - Firewall status
//      - Process status
//      - Full executable path
//
//  The UI automatically refreshes after every operation.
//
// =============================================================================
//
//  7. Main Application Loop
//  ------------------------
//  The application starts from `wWinMain()` which initializes:
//
//      - COM system
//      - Common controls
//      - Main dialog window
//      - Message loop
//
//  The dialog procedure (`MainDlgProc`) handles all user
//  interactions, commands, notifications, and GUI events.
//
// =============================================================================
//
//  Project Goals
//  -----------------------------------------------------------------------------
//
//  FirewallBlocker was designed to provide a lightweight,
//  professional, and efficient Windows utility for managing
//  application-level firewall and execution restrictions.
//
//  The project focuses on:
//
//      - Low resource usage
//      - Native Windows integration
//      - Simplicity and usability
//      - Compatibility with older systems
//      - Clean Win32 programming practices
//
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <comdef.h>
#include <netfw.h>
#include <objbase.h>
#include <atlbase.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include "FirewallBlocker.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

// Enable ComCtl32 v6 for SysLink and visual styles (VS2010 compatible)
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")



// ─── Globals ──────────────────────────────────────────────────────────────────
HINSTANCE g_hInst = NULL;
std::vector<BlockedEntry> g_blockedList;
HWND g_hMenuBar = NULL;  // not used for HMENU but kept for reference

static const wchar_t* IFEO_KEY =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

// ─── Get persistent data path ─────────────────────────────────────────────────
std::wstring GetPersistPath()
{
    wchar_t appData[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
        std::wstring dir = std::wstring(appData) + L"\\FirewallBlocker";
        CreateDirectoryW(dir.c_str(), NULL);
        return dir + L"\\blocked_list.dat";
    }
    // Fallback: same directory as exe
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring s(exePath);
    size_t pos = s.find_last_of(L"\\/");
    if (pos != std::wstring::npos) s = s.substr(0, pos + 1);
    return s + L"blocked_list.dat";
}

// ─── Persistence ──────────────────────────────────────────────────────────────
void SaveList()
{
    std::wstring path = GetPersistPath();
    std::wofstream f(path.c_str(), std::ios::trunc);
    if (!f.is_open()) return;
    for (size_t i = 0; i < g_blockedList.size(); i++) {
        const BlockedEntry& e = g_blockedList[i];
        f << e.filePath    << L"\n"
          << e.fileName    << L"\n"
          << e.ruleName    << L"\n"
          << e.blockType   << L"\n"
          << (e.fwBlocked   ? 1 : 0) << L"\n"
          << (e.procBlocked ? 1 : 0) << L"\n"
          << L"---\n";
    }
}

void LoadList()
{
    g_blockedList.clear();
    std::wstring path = GetPersistPath();
    std::wifstream f(path.c_str());
    if (!f.is_open()) return;
    while (true) {
        BlockedEntry e;
        if (!std::getline(f, e.filePath))  break;
        if (!std::getline(f, e.fileName))  break;
        if (!std::getline(f, e.ruleName))  break;
        std::wstring tmp;
        if (!std::getline(f, tmp)) break; e.blockType   = _wtoi(tmp.c_str());
        if (!std::getline(f, tmp)) break; e.fwBlocked   = (_wtoi(tmp.c_str()) != 0);
        if (!std::getline(f, tmp)) break; e.procBlocked = (_wtoi(tmp.c_str()) != 0);
        std::getline(f, tmp); // "---"
        if (e.filePath.empty()) continue;
        g_blockedList.push_back(e);
    }
}

// ─── Auto-elevate ──────────────────────────────────────────────────────────────
bool IsElevated()
{
    bool elevated = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te = {0};
        DWORD dwSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &dwSize))
            elevated = (te.TokenIsElevated != 0);
        CloseHandle(hToken);
    }
    return elevated;
}

void RelaunchAsAdmin()
{
    wchar_t szPath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = L"runas";
    sei.lpFile       = szPath;
    sei.nShow        = SW_SHOWNORMAL;
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    ShellExecuteExW(&sei);
    ExitProcess(0);
}

// ─── Utilities ────────────────────────────────────────────────────────────────
std::wstring GetFileNameFromPath(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return path;
    return path.substr(pos + 1);
}

std::wstring GetRuleNameFromPath(const std::wstring& path)
{
    return std::wstring(L"FWB_") + GetFileNameFromPath(path);
}

void SetStatus(HWND hDlg, const std::wstring& msg)
{
    SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, (L"Status: " + msg).c_str());
}

// ─── Firewall (INetFwPolicy2) ──────────────────────────────────────────────────
bool AddFirewallRule(const std::wstring& exePath, const std::wstring& ruleName)
{
    CComPtr<INetFwPolicy2> pFwPolicy2;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), (void**)&pFwPolicy2);
    if (FAILED(hr)) return false;

    CComPtr<INetFwRules> pFwRules;
    hr = pFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) return false;

    _bstr_t bPath  = exePath.c_str();
    _bstr_t bDesc  = L"Blocked by FirewallBlocker";
    _bstr_t bGroup = L"FirewallBlocker";

    // Inbound
    CComPtr<INetFwRule> pRuleIn;
    if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER,
                                   __uuidof(INetFwRule), (void**)&pRuleIn))) {
        _bstr_t bNameIn = (ruleName + L"_IN").c_str();
        pRuleIn->put_Name(bNameIn);
        pRuleIn->put_Description(bDesc);
        pRuleIn->put_ApplicationName(bPath);
        pRuleIn->put_Action(NET_FW_ACTION_BLOCK);
        pRuleIn->put_Direction(NET_FW_RULE_DIR_IN);
        pRuleIn->put_Enabled(VARIANT_TRUE);
        pRuleIn->put_Grouping(bGroup);
        pRuleIn->put_Profiles(NET_FW_PROFILE2_ALL);
        pFwRules->Add(pRuleIn);
    }

    // Outbound
    CComPtr<INetFwRule> pRuleOut;
    if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER,
                                   __uuidof(INetFwRule), (void**)&pRuleOut))) {
        _bstr_t bNameOut = (ruleName + L"_OUT").c_str();
        pRuleOut->put_Name(bNameOut);
        pRuleOut->put_Description(bDesc);
        pRuleOut->put_ApplicationName(bPath);
        pRuleOut->put_Action(NET_FW_ACTION_BLOCK);
        pRuleOut->put_Direction(NET_FW_RULE_DIR_OUT);
        pRuleOut->put_Enabled(VARIANT_TRUE);
        pRuleOut->put_Grouping(bGroup);
        pRuleOut->put_Profiles(NET_FW_PROFILE2_ALL);
        hr = pFwRules->Add(pRuleOut);
    }
    return SUCCEEDED(hr);
}

bool RemoveFirewallRule(const std::wstring& ruleName)
{
    CComPtr<INetFwPolicy2> pFwPolicy2;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), (void**)&pFwPolicy2);
    if (FAILED(hr)) return false;
    CComPtr<INetFwRules> pFwRules;
    pFwPolicy2->get_Rules(&pFwRules);
    _bstr_t bIn  = (ruleName + L"_IN").c_str();
    _bstr_t bOut = (ruleName + L"_OUT").c_str();
    pFwRules->Remove(bIn);
    pFwRules->Remove(bOut);
    return true;
}

bool IsFirewallRuleExists(const std::wstring& ruleName)
{
    CComPtr<INetFwPolicy2> pFwPolicy2;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), (void**)&pFwPolicy2);
    if (FAILED(hr)) return false;
    CComPtr<INetFwRules> pFwRules;
    pFwPolicy2->get_Rules(&pFwRules);
    CComPtr<INetFwRule> pRule;
    _bstr_t bIn = (ruleName + L"_IN").c_str();
    return SUCCEEDED(pFwRules->Item(bIn, &pRule));
}

// ─── Process Block via IFEO ────────────────────────────────────────────────────
bool BlockProcessExecution(const std::wstring& exePath, const std::wstring&)
{
    std::wstring exeName = GetFileNameFromPath(exePath);
    std::wstring subKey  = std::wstring(IFEO_KEY) + L"\\" + exeName;

    HKEY hKey = NULL;
    LONG res = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                subKey.c_str(), 0, NULL,
                                REG_OPTION_NON_VOLATILE,
                                KEY_SET_VALUE | KEY_QUERY_VALUE,
                                NULL, &hKey, NULL);
    if (res != ERROR_SUCCESS) return false;

    const wchar_t* blocker = L"C:\\BLOCKED_BY_FIREWALL_BLOCKER.exe";
    res = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ,
                         (const BYTE*)blocker,
                         (DWORD)((wcslen(blocker) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS);
}

bool UnblockProcessExecution(const std::wstring& exePath, const std::wstring&)
{
    std::wstring exeName = GetFileNameFromPath(exePath);
    std::wstring subKey  = std::wstring(IFEO_KEY) + L"\\" + exeName;

    HKEY hKey = NULL;
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(),
                              0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
    if (res != ERROR_SUCCESS) return true;

    RegDeleteValueW(hKey, L"Debugger");
    RegCloseKey(hKey);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, subKey.c_str());
    return true;
}

bool IsProcessBlocked(const std::wstring& exePath)
{
    std::wstring exeName = GetFileNameFromPath(exePath);
    std::wstring subKey  = std::wstring(IFEO_KEY) + L"\\" + exeName;

    HKEY hKey = NULL;
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(),
                              0, KEY_QUERY_VALUE, &hKey);
    if (res != ERROR_SUCCESS) return false;

    wchar_t buf[512] = {0};
    DWORD sz   = sizeof(buf);
    DWORD type = 0;
    res = RegQueryValueExW(hKey, L"Debugger", NULL, &type, (BYTE*)buf, &sz);
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) return false;
    return (wcsstr(buf, L"BLOCKED_BY_FIREWALL_BLOCKER") != NULL);
}

// ─── ListView helpers ─────────────────────────────────────────────────────────
void SetupListView(HWND hList)
{
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMN col = {0};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.pszText = L"File Name";     col.cx = 130; ListView_InsertColumn(hList, 0, &col);
    col.pszText = L"Block Type";    col.cx =  88; ListView_InsertColumn(hList, 1, &col);
    col.pszText = L"Firewall";      col.cx =  62; ListView_InsertColumn(hList, 2, &col);
    col.pszText = L"Process";       col.cx =  62; ListView_InsertColumn(hList, 3, &col);
    col.pszText = L"Full Path";     col.cx = 270; ListView_InsertColumn(hList, 4, &col);
}

void RefreshListView(HWND hList, const std::vector<BlockedEntry>& entries)
{
    ListView_DeleteAllItems(hList);
    for (int i = 0; i < (int)entries.size(); i++) {
        const BlockedEntry& e = entries[i];

        LVITEM lvi = {0};
        lvi.mask    = LVIF_TEXT;
        lvi.iItem   = i;
        lvi.pszText = (LPWSTR)e.fileName.c_str();
        ListView_InsertItem(hList, &lvi);

        std::wstring typeStr;
        if      (e.blockType == BLOCK_BOTH)    typeStr = L"Both";
        else if (e.blockType == BLOCK_FIREWALL) typeStr = L"Firewall";
        else if (e.blockType == BLOCK_PROCESS)  typeStr = L"Running";
        ListView_SetItemText(hList, i, 1, (LPWSTR)typeStr.c_str());

        std::wstring fwStr   = e.fwBlocked   ? L"Blocked" : L"-";
        std::wstring procStr = e.procBlocked  ? L"Blocked" : L"-";
        ListView_SetItemText(hList, i, 2, (LPWSTR)fwStr.c_str());
        ListView_SetItemText(hList, i, 3, (LPWSTR)procStr.c_str());
        ListView_SetItemText(hList, i, 4, (LPWSTR)e.filePath.c_str());
    }
}

// ─── Update block button labels based on selection ────────────────────────────
// When an item is selected in the list, the "Block Firewall" button becomes
// "Unblock Firewall" if already fw-blocked, etc.
// When nothing selected or path is from edit box, revert to "Block ..."
void UpdateBlockButtonLabels(HWND hDlg)
{
    HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);

    if (sel >= 0 && sel < (int)g_blockedList.size()) {
        const BlockedEntry& e = g_blockedList[sel];
        // Firewall button
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_FW,
            e.fwBlocked ? L"Unblock Firewall" : L"Block Firewall");
        // Running button
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_RUN,
            e.procBlocked ? L"Unblock Running" : L"Block Running");
        // Both button
        bool bothBlocked = (e.fwBlocked && e.procBlocked);
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_BOTH,
            bothBlocked ? L"Unblock Both" : L"Block Both");
    } else {
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_FW,   L"Block Firewall");
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_RUN,  L"Block Running");
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_BOTH, L"Block Both");
    }
}

// ─── Center a window on screen ────────────────────────────────────────────────
void CenterWindowOnScreen(HWND hWnd)
{
    RECT rc;
    GetWindowRect(hWnd, &rc);
    int w = rc.right  - rc.left;
    int h = rc.bottom - rc.top;
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hWnd, NULL,
        (sw - w) / 2, (sh - h) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

// ─── About dialog ─────────────────────────────────────────────────────────────
static HFONT g_hFontAboutTitle  = NULL;
static HFONT g_hFontAboutSub    = NULL;
static HFONT g_hFontSectionLabel = NULL;

INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
    {
        HICON hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_FIREWALLBLOCKER));
        SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);

        // Bold large font for app name
        if (!g_hFontAboutTitle) {
            g_hFontAboutTitle = CreateFont(
                -18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        }
        // Regular font for subtitle
        if (!g_hFontAboutSub) {
            g_hFontAboutSub = CreateFont(
                -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        }

        HWND hName = GetDlgItem(hDlg, IDC_ABOUT_NAME);
        HWND hVer  = GetDlgItem(hDlg, IDC_ABOUT_VER);

        if (g_hFontAboutTitle) SendMessage(hName, WM_SETFONT, (WPARAM)g_hFontAboutTitle, TRUE);
        if (g_hFontAboutSub)   SendMessage(hVer,  WM_SETFONT, (WPARAM)g_hFontAboutSub,   TRUE);

        // Ensure centered
        CenterWindowOnScreen(hDlg);

        return (INT_PTR)TRUE;
    }

    case WM_NOTIFY:
    {
        // Handle SysLink click - open GitHub URL in browser
        NMHDR* pnm = (NMHDR*)lParam;
        if (pnm->idFrom == IDC_ABOUT_LINK && pnm->code == NM_CLICK) {
            NMLINK* pnml = (NMLINK*)lParam;
            ShellExecuteW(NULL, L"open", pnml->item.szUrl, NULL, NULL, SW_SHOWNORMAL);
            return (INT_PTR)TRUE;
        }
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        int id = GetDlgCtrlID(hCtrl);
        // Color the app name in accent blue
        if (id == IDC_ABOUT_NAME) {
            SetTextColor(hdc, RGB(0, 102, 204));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
        return (INT_PTR)FALSE;
    }
    }
    return (INT_PTR)FALSE;
}

// ─── Toggle block/unblock for selected item ───────────────────────────────────
// Returns true if an action was performed on a selected item (toggle mode).
// Returns false if we should fall through to "add new" mode.
bool TryToggleSelected(HWND hDlg, int btnId)
{
    HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_blockedList.size()) return false;

    BlockedEntry& e = g_blockedList[sel];

    if (btnId == IDC_BTN_BLOCK_FW) {
        if (e.fwBlocked) {
            // Unblock firewall
            RemoveFirewallRule(e.ruleName);
            e.fwBlocked = false;
            // If process also not blocked, remove from list
            if (!e.procBlocked) {
                g_blockedList.erase(g_blockedList.begin() + sel);
            }
        } else {
            // Block firewall for existing entry
            e.fwBlocked = AddFirewallRule(e.filePath, e.ruleName);
            e.blockType |= BLOCK_FIREWALL;
        }
        SaveList();
        RefreshListView(hList, g_blockedList);
        UpdateBlockButtonLabels(hDlg);
        return true;
    }
    else if (btnId == IDC_BTN_BLOCK_RUN) {
        if (e.procBlocked) {
            UnblockProcessExecution(e.filePath, e.ruleName);
            e.procBlocked = false;
            if (!e.fwBlocked) {
                g_blockedList.erase(g_blockedList.begin() + sel);
            }
        } else {
            e.procBlocked = BlockProcessExecution(e.filePath, e.ruleName);
            e.blockType |= BLOCK_PROCESS;
        }
        SaveList();
        RefreshListView(hList, g_blockedList);
        UpdateBlockButtonLabels(hDlg);
        return true;
    }
    else if (btnId == IDC_BTN_BLOCK_BOTH) {
        bool bothBlocked = (e.fwBlocked && e.procBlocked);
        if (bothBlocked) {
            RemoveFirewallRule(e.ruleName);
            UnblockProcessExecution(e.filePath, e.ruleName);
            g_blockedList.erase(g_blockedList.begin() + sel);
        } else {
            if (!e.fwBlocked)   e.fwBlocked   = AddFirewallRule(e.filePath, e.ruleName);
            if (!e.procBlocked) e.procBlocked  = BlockProcessExecution(e.filePath, e.ruleName);
            e.blockType = BLOCK_BOTH;
        }
        SaveList();
        RefreshListView(hList, g_blockedList);
        UpdateBlockButtonLabels(hDlg);
        return true;
    }
    return false;
}

// ─── Attach a 16x16 icon to a button keeping text visible (ComCtl32 v6) ───────
// BCM_SETIMAGELIST places the icon to the left of the button label.
void SetButtonIcon(HWND hDlg, int btnId, int iconResId)
{
    HWND hBtn = GetDlgItem(hDlg, btnId);
    if (!hBtn) return;

    HICON hIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(iconResId),
        IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    if (!hIcon) return;

    // Create a single-slot ImageList and add the icon
    HIMAGELIST hIL = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 0);
    if (!hIL) return;
    ImageList_ReplaceIcon(hIL, -1, hIcon);
    DestroyIcon(hIcon);

    // BUTTON_IMAGELIST: attach imagelist + set margin + alignment
    BUTTON_IMAGELIST bil = {0};
    bil.himl      = hIL;
    bil.margin.left  = 4;
    bil.margin.right = 4;
    bil.uAlign    = BUTTON_IMAGELIST_ALIGN_LEFT;
    SendMessage(hBtn, BCM_SETIMAGELIST, 0, (LPARAM)&bil);
    // Note: hIL is owned by the button now (do not destroy until button destroyed)
}

// ─── Global modern UI fonts ────────────────────────────────────────────────────
static HFONT g_hFontTitle   = NULL;  // large bold for main title
static HFONT g_hFontSubtitle = NULL; // small regular for subtitle
static HFONT g_hFontSection = NULL;  // small caps-style section labels
static HFONT g_hFontUI      = NULL;  // default Segoe UI for controls

// ─── Main Dialog Procedure ────────────────────────────────────────────────────
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        HICON hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_FIREWALLBLOCKER));
        SendMessage(hDlg, WM_SETICON, ICON_BIG,   (LPARAM)hIcon);
        SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);

        // Create modern fonts
        g_hFontTitle = CreateFont(
            -20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_hFontSubtitle = CreateFont(
            -10, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_hFontSection = CreateFont(
            -9, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_hFontUI = CreateFont(
            -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        // Apply fonts to header controls
        if (g_hFontTitle)
            SendDlgItemMessageW(hDlg, IDC_STATIC_TITLE, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);
        if (g_hFontSubtitle)
            SendDlgItemMessageW(hDlg, IDC_STATIC_SEP, WM_SETFONT, (WPARAM)g_hFontSubtitle, TRUE);
        if (g_hFontSection) {
            SendDlgItemMessageW(hDlg, IDC_STATIC_LIST, WM_SETFONT, (WPARAM)g_hFontSection, TRUE);
        }

        // Apply Segoe UI to all main buttons and edit
        int ctrlIds[] = {
            IDC_BTN_BROWSE, IDC_BTN_BLOCK_FW, IDC_BTN_BLOCK_RUN,
            IDC_BTN_BLOCK_BOTH, IDC_BTN_UNBLOCK, IDC_BTN_REFRESH,
            IDC_EDIT_PATH, IDC_STATIC_PATH, IDC_STATIC_STATUS
        };
        for (int i = 0; i < 9; i++) {
            HWND hCtrl = GetDlgItem(hDlg, ctrlIds[i]);
            if (hCtrl && g_hFontUI)
                SendMessage(hCtrl, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);
        }

        // Attach menu
        HMENU hMenu = LoadMenuW(g_hInst, MAKEINTRESOURCE(IDR_MENU_MAIN));
        SetMenu(hDlg, hMenu);

        SetupListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED));
        LoadList();
        RefreshListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED), g_blockedList);

        // Ensure centered on screen (DS_CENTER should handle this, belt-and-suspenders)
        CenterWindowOnScreen(hDlg);

        // Attach icons to buttons
        SetButtonIcon(hDlg, IDC_BTN_BLOCK_FW,   IDI_BTN_BLOCK_FW);
        SetButtonIcon(hDlg, IDC_BTN_BLOCK_RUN,  IDI_BTN_BLOCK_RUN);
        SetButtonIcon(hDlg, IDC_BTN_BLOCK_BOTH, IDI_BTN_BLOCK_BOTH);
        SetButtonIcon(hDlg, IDC_BTN_UNBLOCK,    IDI_BTN_UNBLOCK);
        SetButtonIcon(hDlg, IDC_BTN_REFRESH,    IDI_BTN_REFRESH);
        SetButtonIcon(hDlg, IDC_BTN_BROWSE,     IDI_BTN_BROWSE);

        if (!IsElevated())
            SetStatus(hDlg, L"WARNING: FWBlock requires Administrator - some features may fail.");
        else
            SetStatus(hDlg, L"FWBlock ready  (Administrator).");

        return (INT_PTR)TRUE;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);

        // ── Menu: Exit ────────────────────────────────────────────────────────
        if (id == IDM_EXIT) {
            DestroyWindow(hDlg);
        }
        // ── Menu: About ───────────────────────────────────────────────────────
        else if (id == IDM_ABOUT) {
            DialogBoxW(g_hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hDlg, AboutDlgProc);
        }
        // ── Menu: Refresh (also toolbar refresh button) ───────────────────────
        else if (id == IDC_BTN_REFRESH) {
            for (size_t i = 0; i < g_blockedList.size(); i++) {
                g_blockedList[i].fwBlocked   = IsFirewallRuleExists(g_blockedList[i].ruleName);
                g_blockedList[i].procBlocked = IsProcessBlocked(g_blockedList[i].filePath);
            }
            SaveList();
            RefreshListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED), g_blockedList);
            UpdateBlockButtonLabels(hDlg);
            SetStatus(hDlg, L"List refreshed.");
        }
        // ── Browse ────────────────────────────────────────────────────────────
        else if (id == IDC_BTN_BROWSE) {
            wchar_t szFile[MAX_PATH] = {0};
            OPENFILENAMEW ofn        = {0};
            ofn.lStructSize = sizeof(OPENFILENAMEW);
            ofn.hwndOwner   = hDlg;
            ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile   = szFile;
            ofn.nMaxFile    = MAX_PATH;
            ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            ofn.lpstrTitle  = L"Select EXE file to block";
            if (GetOpenFileNameW(&ofn)) {
                SetDlgItemTextW(hDlg, IDC_EDIT_PATH, szFile);
                // Deselect list so buttons show "Block ..." not "Unblock ..."
                HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
                ListView_SetItemState(hList, -1, 0, LVIS_SELECTED);
                UpdateBlockButtonLabels(hDlg);
            }
        }
        // ── Block buttons ─────────────────────────────────────────────────────
        else if (id == IDC_BTN_BLOCK_FW  ||
                 id == IDC_BTN_BLOCK_RUN ||
                 id == IDC_BTN_BLOCK_BOTH)
        {
            // First try toggle on selected list item
            if (TryToggleSelected(hDlg, id)) {
                // Done - already handled inside
                // Update status
                HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
                int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
                if (sel >= 0 && sel < (int)g_blockedList.size())
                    SetStatus(hDlg, L"Updated: " + g_blockedList[sel].fileName);
                else
                    SetStatus(hDlg, L"Unblocked and removed from list.");
                break;
            }

            // No selection - use path from edit box (add new entry)
            wchar_t szPath[MAX_PATH] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_PATH, szPath, MAX_PATH);
            std::wstring path(szPath);

            if (path.empty()) {
                MessageBoxW(hDlg,
                    L"Select or type an EXE path first,\nor select an item in the list to toggle its block status.",
                    L"No Target", MB_ICONINFORMATION);
                break;
            }

            DWORD attr      = GetFileAttributesW(path.c_str());
            bool  fileExists = (attr != INVALID_FILE_ATTRIBUTES);

            if (!fileExists && id != IDC_BTN_BLOCK_FW) {
                MessageBoxW(hDlg,
                    L"File not found!\n\nBlock Running (IFEO) requires a valid EXE path.",
                    L"File Not Found", MB_ICONERROR);
                break;
            }
            if (!fileExists && id == IDC_BTN_BLOCK_FW) {
                int r = MessageBoxW(hDlg,
                    L"File not found. Continue adding firewall rule anyway?",
                    L"File Not Found", MB_YESNO | MB_ICONQUESTION);
                if (r != IDYES) break;
            }

            std::wstring fname    = GetFileNameFromPath(path);
            std::wstring ruleName = GetRuleNameFromPath(path);

            // Check duplicate
            for (size_t i = 0; i < g_blockedList.size(); i++) {
                if (_wcsicmp(g_blockedList[i].filePath.c_str(), path.c_str()) == 0) {
                    MessageBoxW(hDlg, L"This file is already in the blocked list.\nSelect it in the list to toggle.",
                                L"Already Listed", MB_ICONINFORMATION);
                    goto done;
                }
            }

            {
                BlockedEntry entry;
                entry.filePath    = path;
                entry.fileName    = fname;
                entry.ruleName    = ruleName;
                entry.blockType   = BLOCK_FIREWALL;
                entry.fwBlocked   = false;
                entry.procBlocked = false;

                if (id == IDC_BTN_BLOCK_FW || id == IDC_BTN_BLOCK_BOTH) {
                    entry.blockType = (id == IDC_BTN_BLOCK_BOTH) ? BLOCK_BOTH : BLOCK_FIREWALL;
                    entry.fwBlocked = AddFirewallRule(path, ruleName);
                    if (!entry.fwBlocked) {
                        MessageBoxW(hDlg,
                            L"Failed to add firewall rule.\nMake sure the application runs as Administrator.",
                            L"Firewall Error", MB_ICONERROR);
                    }
                }

                if (id == IDC_BTN_BLOCK_RUN || id == IDC_BTN_BLOCK_BOTH) {
                    if (id == IDC_BTN_BLOCK_RUN) entry.blockType = BLOCK_PROCESS;
                    entry.procBlocked = BlockProcessExecution(path, ruleName);
                    if (!entry.procBlocked) {
                        MessageBoxW(hDlg,
                            L"Failed to block process via IFEO.\nMake sure the application runs as Administrator.",
                            L"Process Block Error", MB_ICONERROR);
                    }
                }

                g_blockedList.push_back(entry);
                SaveList();
                RefreshListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED), g_blockedList);

                std::wstring statusMsg;
                if      (entry.fwBlocked && entry.procBlocked) statusMsg = L"Firewall + Process blocked: " + fname;
                else if (entry.fwBlocked)   statusMsg = L"Firewall blocked: " + fname;
                else if (entry.procBlocked) statusMsg = L"Process blocked: " + fname;
                else                        statusMsg = L"Block failed: " + fname;
                SetStatus(hDlg, statusMsg);
            }
            done:;
        }
        // ── Unblock selected ──────────────────────────────────────────────────
        else if (id == IDC_BTN_UNBLOCK) {
            HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= (int)g_blockedList.size()) {
                MessageBoxW(hDlg, L"Select an item in the list first.",
                            L"Nothing Selected", MB_ICONINFORMATION);
                break;
            }
            BlockedEntry& e = g_blockedList[sel];
            int r = MessageBoxW(hDlg,
                (L"Unblock:\n" + e.filePath + L"\n\nContinue?").c_str(),
                L"Confirm Unblock", MB_YESNO | MB_ICONQUESTION);
            if (r != IDYES) break;

            if (e.fwBlocked)   RemoveFirewallRule(e.ruleName);
            if (e.procBlocked) UnblockProcessExecution(e.filePath, e.ruleName);

            std::wstring fname = e.fileName;
            g_blockedList.erase(g_blockedList.begin() + sel);
            SaveList();
            RefreshListView(hList, g_blockedList);
            UpdateBlockButtonLabels(hDlg);
            SetStatus(hDlg, L"Unblocked and removed: " + fname);
        }

        break;
    }

    case WM_NOTIFY:
    {
        NMHDR* pNMHDR = (NMHDR*)lParam;
        if (pNMHDR->idFrom == IDC_LIST_BLOCKED) {
            if (pNMHDR->code == LVN_ITEMCHANGED) {
                UpdateBlockButtonLabels(hDlg);
            }
        }
        break;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        int id = GetDlgCtrlID(hCtrl);

        // Main title in accent blue
        if (id == IDC_STATIC_TITLE) {
            SetTextColor(hdc, RGB(0, 102, 204));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
        // Subtitle and section labels in grey
        if (id == IDC_STATIC_SEP || id == IDC_STATIC_LIST) {
            SetTextColor(hdc, RGB(100, 100, 100));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
        return (INT_PTR)FALSE;
    }

    case WM_CLOSE:
        DestroyWindow(hDlg);
        break;
    case WM_DESTROY:
        // Clean up fonts
        if (g_hFontTitle)    { DeleteObject(g_hFontTitle);    g_hFontTitle    = NULL; }
        if (g_hFontSubtitle) { DeleteObject(g_hFontSubtitle); g_hFontSubtitle = NULL; }
        if (g_hFontSection)  { DeleteObject(g_hFontSection);  g_hFontSection  = NULL; }
        if (g_hFontUI)       { DeleteObject(g_hFontUI);       g_hFontUI       = NULL; }
        if (g_hFontAboutTitle) { DeleteObject(g_hFontAboutTitle); g_hFontAboutTitle = NULL; }
        if (g_hFontAboutSub)   { DeleteObject(g_hFontAboutSub);   g_hFontAboutSub   = NULL; }
        PostQuitMessage(0);
        break;
    }
    return (INT_PTR)FALSE;
}

// ─── WinMain ──────────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int)
{
    g_hInst = hInstance;

    // Auto-elevate if not administrator
    if (!IsElevated()) {
        RelaunchAsAdmin();
        return 0;
    }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_LISTVIEW_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    HWND hDlg = CreateDialogW(hInstance,
                               MAKEINTRESOURCE(IDD_FIREWALLBLOCKER_DIALOG),
                               NULL, MainDlgProc);
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    CoUninitialize();
    return (int)msg.wParam;
}
