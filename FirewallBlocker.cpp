// =============================================================================
//  FirewallBlocker.cpp  -  v1.1 with Scheduled Blocking + Password Protection
//                          + System Tray + Realtime Scheduler via schtasks
// =============================================================================
//  Author      : Ari Sohandri Putra
//  Repository  : https://github.com/arisohandriputra/FWBlock
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
#include <locale>
#include <codecvt>
#include "FirewallBlocker.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ─── Globals ──────────────────────────────────────────────────────────────────
HINSTANCE g_hInst = NULL;
std::vector<BlockedEntry>  g_blockedList;
std::vector<ScheduleEntry> g_scheduleList;
static NOTIFYICONDATAW     g_nid = {0};
static bool                g_trayAdded = false;

static const wchar_t* IFEO_KEY =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
static const wchar_t* TASK_PREFIX = L"FWBlock_Sched_";

// ─── Password hash (FNV-1a 32-bit) ───────────────────────────────────────────
std::wstring HashPassword(const std::wstring& pw)
{
    if (pw.empty()) return L"";
    unsigned int hash = 2166136261u;
    for (size_t i = 0; i < pw.size(); i++) {
        hash ^= (unsigned int)pw[i];
        hash *= 16777219u;
    }
    wchar_t buf[16] = {0};
    wsprintfW(buf, L"%08X", hash);
    return std::wstring(buf);
}

// ─── Paths ────────────────────────────────────────────────────────────────────
std::wstring GetAppDataDir()
{
    wchar_t appData[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
        std::wstring dir = std::wstring(appData) + L"\\FirewallBlocker";
        CreateDirectoryW(dir.c_str(), NULL);
        return dir;
    }
    wchar_t exePath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring s(exePath);
    size_t pos = s.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? s.substr(0, pos + 1) : s;
}

std::wstring GetPersistPath()   { return GetAppDataDir() + L"\\blocked_list.dat"; }
std::wstring GetSchedulePath()  { return GetAppDataDir() + L"\\schedule_list.dat"; }

// ─── SYSTEMTIME helpers ───────────────────────────────────────────────────────
int CompareSysTime(const SYSTEMTIME& a, const SYSTEMTIME& b)
{
    FILETIME fa, fb;
    SystemTimeToFileTime(&a, &fa);
    SystemTimeToFileTime(&b, &fb);
    return CompareFileTime(&fa, &fb);
}

std::wstring FormatSysTime(const SYSTEMTIME& st)
{
    wchar_t buf[64] = {0};
    wsprintfW(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::wstring(buf);
}

static void WriteWideFile(const std::wstring& path, const std::wstring& content)
{
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    // Write UTF-16 LE BOM
    WORD bom = 0xFEFF;
    DWORD dw = 0;
    WriteFile(hf, &bom, 2, &dw, NULL);
    if (!content.empty())
        WriteFile(hf, content.c_str(),
                  (DWORD)(content.size() * sizeof(wchar_t)), &dw, NULL);
    CloseHandle(hf);
}

static std::wstring ReadWideFile(const std::wstring& path)
{
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return L"";
    DWORD sz = GetFileSize(hf, NULL);
    if (sz < 2) { CloseHandle(hf); return L""; }
    std::vector<BYTE> buf(sz);
    DWORD read = 0;
    ReadFile(hf, buf.data(), sz, &read, NULL);
    CloseHandle(hf);
    // detect BOM
    int offset = 0;
    if (buf.size() >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) offset = 2; // UTF-16 LE BOM
    else if (buf.size() >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) {
        // UTF-16 BE - unlikely but handle gracefully: return empty
        return L"";
    }
    // Check if it looks like UTF-16 (every other byte in ASCII range suggests otherwise)
    // Simple heuristic: if offset=0, check if null bytes are present (UTF-16 pattern)
    bool isUtf16 = (offset == 2);
    if (!isUtf16 && buf.size() > 4) {
        // Check for embedded nulls
        int nulls = 0;
        for (size_t i = 1; i < (size_t)sz && i < 20; i += 2) if (buf[i] == 0) nulls++;
        if (nulls > 3) isUtf16 = true;
    }
    if (isUtf16) {
        size_t wlen = (sz - offset) / 2;
        if (wlen == 0) return L"";
        std::wstring ws(wlen, L'\0');
        memcpy(&ws[0], buf.data() + offset, wlen * 2);
        return ws;
    }
    // Fallback: treat as ANSI
    std::string ansi((char*)buf.data(), sz);
    int wlen2 = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), (int)ansi.size(), NULL, 0);
    if (wlen2 <= 0) return L"";
    std::wstring ws(wlen2, L'\0');
    if (!ws.empty())
        MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), (int)ansi.size(), &ws[0], wlen2);
    return ws;
}

// Split wstring by newline
static std::vector<std::wstring> SplitLines(const std::wstring& s)
{
    std::vector<std::wstring> lines;
    std::wstringstream ss(s);
    std::wstring line;
    while (std::getline(ss, line)) {
        // trim \r
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        lines.push_back(line);
    }
    // Remove trailing empty lines so they don't fool entry-count checks
    while (!lines.empty() && lines.back().empty())
        lines.pop_back();
    return lines;
}

// ─── Persistence: blocked list ────────────────────────────────────────────────
void SaveList()
{
    std::wstring content;
    content += L"FWBBLOCK_V2\n"; // version header
    for (size_t i = 0; i < g_blockedList.size(); i++) {
        const BlockedEntry& e = g_blockedList[i];
        wchar_t tmp[32];
        content += e.filePath + L"\n";
        content += e.fileName + L"\n";
        content += e.ruleName + L"\n";
        wsprintfW(tmp, L"%d", e.blockType);   content += tmp; content += L"\n";
        wsprintfW(tmp, L"%d", e.fwBlocked   ? 1 : 0); content += tmp; content += L"\n";
        wsprintfW(tmp, L"%d", e.procBlocked ? 1 : 0); content += tmp; content += L"\n";
        content += e.passwordHash + L"\n";
        content += L"---\n";
    }
    WriteWideFile(GetPersistPath(), content);
}

void LoadList()
{
    g_blockedList.clear();
    std::wstring raw = ReadWideFile(GetPersistPath());
    if (raw.empty()) return;
    std::vector<std::wstring> lines = SplitLines(raw);
    if (lines.empty()) return;
    // Reject files without version header (old/corrupted format)
    if (lines[0] != L"FWBBLOCK_V2") {
        WriteWideFile(GetPersistPath(), L"FWBBLOCK_V2\n");
        return;
    }
    size_t i = 1; // skip version header
    // Each entry = 7 data fields + 1 separator "---" = 8 lines minimum
    while (i + 8 <= lines.size()) {
        BlockedEntry e;
        e.filePath    = lines[i++];
        e.fileName    = lines[i++];
        e.ruleName    = lines[i++];
        e.blockType   = _wtoi(lines[i++].c_str());
        e.fwBlocked   = (_wtoi(lines[i++].c_str()) != 0);
        e.procBlocked = (_wtoi(lines[i++].c_str()) != 0);
        e.passwordHash= lines[i++];
        if (i < lines.size() && lines[i] == L"---") i++;
        if (e.filePath.empty()) continue;
        g_blockedList.push_back(e);
    }
}

// ─── Persistence: schedule list ───────────────────────────────────────────────
// Pack SYSTEMTIME into a single string "YYYY-MM-DD HH:MM:SS"
static std::wstring PackTime(const SYSTEMTIME& st)
{
    wchar_t buf[32] = {0};
    wsprintfW(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
              (int)st.wYear, (int)st.wMonth, (int)st.wDay,
              (int)st.wHour, (int)st.wMinute, (int)st.wSecond);
    return buf;
}
// Unpack "YYYY-MM-DD HH:MM:SS" back into SYSTEMTIME; returns false if format wrong
static bool UnpackTime(const std::wstring& s, SYSTEMTIME& st)
{
    ZeroMemory(&st, sizeof(st));
    if (s.size() < 16) return false;
    st.wYear   = (WORD)_wtoi(s.substr(0,4).c_str());
    st.wMonth  = (WORD)_wtoi(s.substr(5,2).c_str());
    st.wDay    = (WORD)_wtoi(s.substr(8,2).c_str());
    st.wHour   = (WORD)_wtoi(s.substr(11,2).c_str());
    st.wMinute = (WORD)_wtoi(s.substr(14,2).c_str());
    if (s.size() >= 19) st.wSecond = (WORD)_wtoi(s.substr(17,2).c_str());
    return (st.wYear >= 2000 && st.wYear <= 2100 &&
            st.wMonth >= 1  && st.wMonth <= 12 &&
            st.wDay   >= 1  && st.wDay   <= 31);
}

void SaveScheduleList()
{
    std::wstring content;
    content += L"FWBSCHED_V4\n"; // V4: datetime stored with seconds "YYYY-MM-DD HH:MM:SS"
    for (size_t i = 0; i < g_scheduleList.size(); i++) {
        const ScheduleEntry& s = g_scheduleList[i];
        wchar_t tmp[32];
        content += s.filePath  + L"\n";
        content += s.fileName  + L"\n";
        wsprintfW(tmp, L"%d", s.blockType);          content += tmp; content += L"\n";
        content += PackTime(s.startTime)             + L"\n";
        content += PackTime(s.endTime)               + L"\n";
        wsprintfW(tmp, L"%d", s.hasEnd    ? 1 : 0);  content += tmp; content += L"\n";
        wsprintfW(tmp, L"%d", s.triggered ? 1 : 0);  content += tmp; content += L"\n";
        wsprintfW(tmp, L"%d", s.ended     ? 1 : 0);  content += tmp; content += L"\n";
        content += s.passwordHash + L"\n";
        content += L"---\n";
    }
    WriteWideFile(GetSchedulePath(), content);
}

void LoadScheduleList()
{
    g_scheduleList.clear();
    std::wstring raw = ReadWideFile(GetSchedulePath());
    if (raw.empty()) return;
    std::vector<std::wstring> lines = SplitLines(raw);
    if (lines.empty()) return;
    // Reject any file that doesn't have our current version header
    if (lines[0] != L"FWBSCHED_V4") {
        WriteWideFile(GetSchedulePath(), L"FWBSCHED_V4\n");
        return;
    }
    size_t i = 1; // skip version header
    // Each entry = 9 data fields + 1 separator "---" = 10 lines
    while (i + 10 <= lines.size()) {
        ScheduleEntry s;
        s.filePath  = lines[i++];
        s.fileName  = lines[i++];
        s.blockType = _wtoi(lines[i++].c_str());
        if (!UnpackTime(lines[i++], s.startTime)) { i += 6; continue; } // bad start
        if (!UnpackTime(lines[i++], s.endTime))   { ZeroMemory(&s.endTime, sizeof(s.endTime)); } // bad end ok
        s.hasEnd    = (_wtoi(lines[i++].c_str()) != 0);
        s.triggered = (_wtoi(lines[i++].c_str()) != 0);
        s.ended     = (_wtoi(lines[i++].c_str()) != 0);
        s.passwordHash = lines[i++];
        if (i < lines.size() && lines[i] == L"---") i++;
        if (s.filePath.empty()) continue;
        if (s.ended) continue; // skip already-completed entries from old sessions
        g_scheduleList.push_back(s);
    }
}

// ─── Elevation ────────────────────────────────────────────────────────────────
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
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = szPath;
    sei.nShow  = SW_SHOWNORMAL;
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    ShellExecuteExW(&sei);
    ExitProcess(0);
}

// ─── Autostart (Run with Windows) ─────────────────────────────────────────────
static const wchar_t* AUTOSTART_KEY  = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
static const wchar_t* AUTOSTART_NAME = L"FWBlock";

bool IsAutostartEnabled()
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, AUTOSTART_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, size = 0;
    bool exists = (RegQueryValueExW(hKey, AUTOSTART_NAME, NULL, &type, NULL, &size) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return exists;
}

void SetAutostart(bool enable)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, AUTOSTART_KEY, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    if (enable) {
        wchar_t exePath[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        // Launch silently to tray on startup
        std::wstring cmd = L"\"";
        cmd += exePath;
        cmd += L"\" /silent";
        RegSetValueExW(hKey, AUTOSTART_NAME, 0, REG_SZ,
                       (const BYTE*)cmd.c_str(),
                       (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(hKey, AUTOSTART_NAME);
    }
    RegCloseKey(hKey);
}

void ToggleAutostart()
{
    SetAutostart(!IsAutostartEnabled());
}

// Update checkmark on "Start with Windows" menu items
void UpdateAutostartMenuCheck(HWND hDlg)
{
    bool enabled = IsAutostartEnabled();
    HMENU hMenuBar = GetMenu(hDlg);
    if (hMenuBar) {
        CheckMenuItem(hMenuBar, IDM_AUTOSTART,
                      MF_BYCOMMAND | (enabled ? MF_CHECKED : MF_UNCHECKED));
        DrawMenuBar(hDlg);
    }
}

// ─── Utilities ────────────────────────────────────────────────────────────────
std::wstring GetFileNameFromPath(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
}

std::wstring GetRuleNameFromPath(const std::wstring& path)
{
    return std::wstring(L"FWB_") + GetFileNameFromPath(path);
}

void SetStatus(HWND hDlg, const std::wstring& msg)
{
    SetDlgItemTextW(hDlg, IDC_STATIC_STATUS, (L"Status: " + msg).c_str());
}

// ─── Firewall ─────────────────────────────────────────────────────────────────
bool AddFirewallRule(const std::wstring& exePath, const std::wstring& ruleName)
{
    CComPtr<INetFwPolicy2> pFwPolicy2;
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                                __uuidof(INetFwPolicy2), (void**)&pFwPolicy2))) return false;
    CComPtr<INetFwRules> pFwRules;
    if (FAILED(pFwPolicy2->get_Rules(&pFwRules))) return false;
    _bstr_t bPath  = exePath.c_str();
    _bstr_t bDesc  = L"Blocked by FirewallBlocker";
    _bstr_t bGroup = L"FirewallBlocker";
    CComPtr<INetFwRule> pIn;
    if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER,
                                   __uuidof(INetFwRule), (void**)&pIn))) {
        _bstr_t bNameIn = (ruleName + L"_IN").c_str();
        pIn->put_Name(bNameIn); pIn->put_Description(bDesc);
        pIn->put_ApplicationName(bPath); pIn->put_Action(NET_FW_ACTION_BLOCK);
        pIn->put_Direction(NET_FW_RULE_DIR_IN); pIn->put_Enabled(VARIANT_TRUE);
        pIn->put_Grouping(bGroup); pIn->put_Profiles(NET_FW_PROFILE2_ALL);
        pFwRules->Add(pIn);
    }
    CComPtr<INetFwRule> pOut;
    HRESULT hr = E_FAIL;
    if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER,
                                   __uuidof(INetFwRule), (void**)&pOut))) {
        _bstr_t bNameOut = (ruleName + L"_OUT").c_str();
        pOut->put_Name(bNameOut); pOut->put_Description(bDesc);
        pOut->put_ApplicationName(bPath); pOut->put_Action(NET_FW_ACTION_BLOCK);
        pOut->put_Direction(NET_FW_RULE_DIR_OUT); pOut->put_Enabled(VARIANT_TRUE);
        pOut->put_Grouping(bGroup); pOut->put_Profiles(NET_FW_PROFILE2_ALL);
        hr = pFwRules->Add(pOut);
    }
    return SUCCEEDED(hr);
}

bool RemoveFirewallRule(const std::wstring& ruleName)
{
    CComPtr<INetFwPolicy2> pFwPolicy2;
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                                __uuidof(INetFwPolicy2), (void**)&pFwPolicy2))) return false;
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
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                                __uuidof(INetFwPolicy2), (void**)&pFwPolicy2))) return false;
    CComPtr<INetFwRules> pFwRules;
    pFwPolicy2->get_Rules(&pFwRules);
    CComPtr<INetFwRule> pRule;
    _bstr_t bIn = (ruleName + L"_IN").c_str();
    return SUCCEEDED(pFwRules->Item(bIn, &pRule));
}

// ─── Process Block (IFEO) ─────────────────────────────────────────────────────
bool BlockProcessExecution(const std::wstring& exePath, const std::wstring&)
{
    std::wstring exeName = GetFileNameFromPath(exePath);
    std::wstring subKey  = std::wstring(IFEO_KEY) + L"\\" + exeName;
    HKEY hKey = NULL;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE,
                        NULL, &hKey, NULL) != ERROR_SUCCESS) return false;
    const wchar_t* blocker = L"C:\\BLOCKED_BY_FIREWALL_BLOCKER.exe";
    LONG res = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ,
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
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(),
                      0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"Debugger");
        RegCloseKey(hKey);
    }
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, subKey.c_str());
    return true;
}

bool IsProcessBlocked(const std::wstring& exePath)
{
    std::wstring exeName = GetFileNameFromPath(exePath);
    std::wstring subKey  = std::wstring(IFEO_KEY) + L"\\" + exeName;
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(),
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) return false;
    wchar_t buf[512] = {0};
    DWORD sz = sizeof(buf), type = 0;
    LONG res = RegQueryValueExW(hKey, L"Debugger", NULL, &type, (BYTE*)buf, &sz);
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS && wcsstr(buf, L"BLOCKED_BY_FIREWALL_BLOCKER") != NULL);
}

// ─── Windows Task Scheduler integration (realtime scheduling) ─────────────────
// Register a Windows Scheduled Task so the block persists even if FWBlock is closed.
// The task calls FWBlock.exe itself with a trigger at start/end time.
// We use schtasks.exe for simplicity (works on XP+).

std::wstring GetSelfPath()
{
    wchar_t buf[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buf, MAX_PATH);
    return buf;
}

// Make a safe task name from schedule index
std::wstring MakeTaskName(size_t idx)
{
    wchar_t buf[64] = {0};
    wsprintfW(buf, L"%ls%04d", TASK_PREFIX, (int)idx);
    return buf;
}
std::wstring MakeTaskNameEnd(size_t idx)
{
    wchar_t buf[64] = {0};
    wsprintfW(buf, L"%ls%04d_end", TASK_PREFIX, (int)idx);
    return buf;
}

// Format SYSTEMTIME for schtasks /ST HH:MM and /SD MM/DD/YYYY
std::wstring FormatTaskTime(const SYSTEMTIME& st)
{
    wchar_t buf[16] = {0};
    wsprintfW(buf, L"%02d:%02d", st.wHour, st.wMinute);
    return buf;
}

std::wstring FormatTaskDate(const SYSTEMTIME& st)
{
    wchar_t buf[16] = {0};
    wsprintfW(buf, L"%02d/%02d/%04d", st.wMonth, st.wDay, st.wYear);
    return buf;
}

static void RunHiddenCmd(const wchar_t* cmd)
{
    STARTUPINFOW si = {0}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    wchar_t buf[4096] = {0};
    wsprintfW(buf, L"cmd.exe /c %ls", cmd);
    CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
}

// Register Windows Tasks for start (and end if applicable)
// Uses /dotask <name> for start, /dotask-end <name> for end
void RegisterWindowsTask(size_t schedIdx)
{
    if (schedIdx >= g_scheduleList.size()) return;
    const ScheduleEntry& se = g_scheduleList[schedIdx];
    std::wstring selfPath  = GetSelfPath();

    // --- Start task ---
    std::wstring taskName  = MakeTaskName(schedIdx);
    std::wstring startDate = FormatTaskDate(se.startTime);
    std::wstring startTime = FormatTaskTime(se.startTime);
    wchar_t cmd[4096] = {0};
    wsprintfW(cmd,
        L"schtasks /create /f /tn \"%ls\" /tr \"\\\"%ls\\\" /dotask %ls\" "
        L"/sc once /sd %ls /st %ls /rl highest",
        taskName.c_str(), selfPath.c_str(), taskName.c_str(),
        startDate.c_str(), startTime.c_str());
    RunHiddenCmd(cmd);

    // --- End task (only if schedule has an end time) ---
    if (se.hasEnd) {
        std::wstring endTaskName = MakeTaskNameEnd(schedIdx);
        std::wstring endDate     = FormatTaskDate(se.endTime);
        std::wstring endTime     = FormatTaskTime(se.endTime);
        wsprintfW(cmd,
            L"schtasks /create /f /tn \"%ls\" /tr \"\\\"%ls\\\" /dotask-end %ls\" "
            L"/sc once /sd %ls /st %ls /rl highest",
            endTaskName.c_str(), selfPath.c_str(), taskName.c_str(),
            endDate.c_str(), endTime.c_str());
        RunHiddenCmd(cmd);
    }
}

void DeleteWindowsTask(size_t schedIdx)
{
    // Delete start task
    std::wstring taskName = MakeTaskName(schedIdx);
    wchar_t cmdBuf[512] = {0};
    wsprintfW(cmdBuf, L"schtasks /delete /f /tn \"%ls\"", taskName.c_str());
    RunHiddenCmd(cmdBuf);
    // Delete end task
    std::wstring endTaskName = MakeTaskNameEnd(schedIdx);
    wsprintfW(cmdBuf, L"schtasks /delete /f /tn \"%ls\"", endTaskName.c_str());
    RunHiddenCmd(cmdBuf);
}

// ─── System Tray ──────────────────────────────────────────────────────────────
void AddTrayIcon(HWND hDlg)
{
    if (g_trayAdded) return;
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd   = hDlg;
    g_nid.uID    = TRAY_ICON_ID;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon  = LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_FIREWALLBLOCKER));
    wcscpy_s(g_nid.szTip, L"FWBlock - Firewall & Process Blocker");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
    g_trayAdded = true;
}

void RemoveTrayIcon()
{
    if (!g_trayAdded) return;
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    g_trayAdded = false;
}

void ShowTrayNotification(const std::wstring& title, const std::wstring& msg)
{
    if (!g_trayAdded) return;
    NOTIFYICONDATAW nid = g_nid;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    nid.uTimeout = 5000;
    wcscpy_s(nid.szInfoTitle, title.c_str());
    wcscpy_s(nid.szInfo, msg.c_str());
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// ─── ListView: Blocked List ───────────────────────────────────────────────────
void SetupListView(HWND hList)
{
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    LVCOLUMN col = {0};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = L"File Name";   col.cx = 110; ListView_InsertColumn(hList, 0, &col);
    col.pszText = L"Block Type";  col.cx =  70; ListView_InsertColumn(hList, 1, &col);
    col.pszText = L"Firewall";    col.cx =  54; ListView_InsertColumn(hList, 2, &col);
    col.pszText = L"Process";     col.cx =  54; ListView_InsertColumn(hList, 3, &col);
    col.pszText = L"PW";          col.cx =  28; ListView_InsertColumn(hList, 4, &col);
    col.pszText = L"Full Path";   col.cx = 190; ListView_InsertColumn(hList, 5, &col);
}

void RefreshListView(HWND hList, const std::vector<BlockedEntry>& entries)
{
    ListView_DeleteAllItems(hList);
    for (int i = 0; i < (int)entries.size(); i++) {
        const BlockedEntry& e = entries[i];
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT; lvi.iItem = i;
        lvi.pszText = (LPWSTR)e.fileName.c_str();
        ListView_InsertItem(hList, &lvi);
        std::wstring typeStr = (e.blockType == BLOCK_BOTH) ? L"Both" :
                               (e.blockType == BLOCK_FIREWALL) ? L"Firewall" : L"Running";
        ListView_SetItemText(hList, i, 1, (LPWSTR)typeStr.c_str());
        std::wstring fwStr   = e.fwBlocked   ? L"Blocked" : L"-";
        std::wstring procStr = e.procBlocked  ? L"Blocked" : L"-";
        std::wstring pwStr   = e.passwordHash.empty() ? L"-" : L"Yes";
        ListView_SetItemText(hList, i, 2, (LPWSTR)fwStr.c_str());
        ListView_SetItemText(hList, i, 3, (LPWSTR)procStr.c_str());
        ListView_SetItemText(hList, i, 4, (LPWSTR)pwStr.c_str());
        ListView_SetItemText(hList, i, 5, (LPWSTR)e.filePath.c_str());
    }
}

// ─── ListView: Schedule List ──────────────────────────────────────────────────
void SetupScheduleListView(HWND hList)
{
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    LVCOLUMN col = {0};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = L"File";      col.cx =  80; ListView_InsertColumn(hList, 0, &col);
    col.pszText = L"Type";      col.cx =  38; ListView_InsertColumn(hList, 1, &col);
    col.pszText = L"Start";     col.cx = 118; ListView_InsertColumn(hList, 2, &col);
    col.pszText = L"End";       col.cx = 118; ListView_InsertColumn(hList, 3, &col);
    col.pszText = L"Status";    col.cx =  52; ListView_InsertColumn(hList, 4, &col);
}

void RefreshScheduleListView(HWND hList)
{
    ListView_DeleteAllItems(hList);
    for (int i = 0; i < (int)g_scheduleList.size(); i++) {
        const ScheduleEntry& s = g_scheduleList[i];
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT; lvi.iItem = i;
        lvi.pszText = (LPWSTR)s.fileName.c_str();
        ListView_InsertItem(hList, &lvi);
        std::wstring typeStr = (s.blockType == BLOCK_BOTH) ? L"Both" :
                               (s.blockType == BLOCK_FIREWALL) ? L"FW" : L"Proc";
        ListView_SetItemText(hList, i, 1, (LPWSTR)typeStr.c_str());
        std::wstring startStr = FormatSysTime(s.startTime);
        ListView_SetItemText(hList, i, 2, (LPWSTR)startStr.c_str());
        std::wstring endStr = s.hasEnd ? FormatSysTime(s.endTime) : L"(permanent)";
        ListView_SetItemText(hList, i, 3, (LPWSTR)endStr.c_str());
        std::wstring statStr = s.ended ? L"Done" : (s.triggered ? L"Active" : L"Pending");
        ListView_SetItemText(hList, i, 4, (LPWSTR)statStr.c_str());
    }
}

// ─── Update block button labels ───────────────────────────────────────────────
void UpdateBlockButtonLabels(HWND hDlg)
{
    HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel >= 0 && sel < (int)g_blockedList.size()) {
        const BlockedEntry& e = g_blockedList[sel];
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_FW,
            e.fwBlocked ? L"Unblock Firewall" : L"Block Firewall");
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_RUN,
            e.procBlocked ? L"Unblock Running" : L"Block Running");
        bool bothBlocked = (e.fwBlocked && e.procBlocked);
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_BOTH,
            bothBlocked ? L"Unblock Both" : L"Block Both");
    } else {
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_FW,   L"Block Firewall");
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_RUN,  L"Block Running");
        SetDlgItemTextW(hDlg, IDC_BTN_BLOCK_BOTH, L"Block Both");
    }
}

void CenterWindowOnScreen(HWND hWnd)
{
    RECT rc; GetWindowRect(hWnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    SetWindowPos(hWnd, NULL,
        (GetSystemMetrics(SM_CXSCREEN) - w) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - h) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

// ─── Button icons ─────────────────────────────────────────────────────────────
void SetButtonIcon(HWND hDlg, int btnId, int iconResId)
{
    HWND hBtn = GetDlgItem(hDlg, btnId);
    if (!hBtn) return;
    HICON hIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(iconResId),
                                    IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    if (!hIcon) return;
    HIMAGELIST hIL = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 0);
    if (!hIL) return;
    ImageList_ReplaceIcon(hIL, -1, hIcon);
    DestroyIcon(hIcon);
    BUTTON_IMAGELIST bil = {0};
    bil.himl = hIL; bil.margin.left = 4; bil.margin.right = 4;
    bil.uAlign = BUTTON_IMAGELIST_ALIGN_LEFT;
    SendMessage(hBtn, BCM_SETIMAGELIST, 0, (LPARAM)&bil);
}

// ─── Password Dialog ──────────────────────────────────────────────────────────
struct PasswordDlgData {
    std::wstring outHash;
};

INT_PTR CALLBACK PasswordDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static PasswordDlgData* pData = NULL;
    switch (msg) {
    case WM_INITDIALOG:
        pData = (PasswordDlgData*)lParam;
        CenterWindowOnScreen(hDlg);
        EnableWindow(GetDlgItem(hDlg, IDC_EDIT_PASSWORD), FALSE);
        EnableWindow(GetDlgItem(hDlg, IDC_EDIT_PASSWORD_CONFIRM), FALSE);
        return (INT_PTR)TRUE;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_CHECK_USE_PASSWORD) {
            bool checked = (IsDlgButtonChecked(hDlg, IDC_CHECK_USE_PASSWORD) == BST_CHECKED);
            EnableWindow(GetDlgItem(hDlg, IDC_EDIT_PASSWORD), checked);
            EnableWindow(GetDlgItem(hDlg, IDC_EDIT_PASSWORD_CONFIRM), checked);
        }
        else if (id == IDOK) {
            bool usePw = (IsDlgButtonChecked(hDlg, IDC_CHECK_USE_PASSWORD) == BST_CHECKED);
            if (!usePw) { pData->outHash = L""; EndDialog(hDlg, IDOK); return (INT_PTR)TRUE; }
            wchar_t pw1[128] = {0}, pw2[128] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD,         pw1, 128);
            GetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD_CONFIRM, pw2, 128);
            if (wcscmp(pw1, pw2) != 0) {
                MessageBoxW(hDlg, L"Passwords do not match!", L"Error", MB_ICONERROR);
                return (INT_PTR)TRUE;
            }
            if (wcslen(pw1) == 0) {
                MessageBoxW(hDlg, L"Password cannot be empty if protection is enabled.", L"Error", MB_ICONERROR);
                return (INT_PTR)TRUE;
            }
            pData->outHash = HashPassword(std::wstring(pw1));
            EndDialog(hDlg, IDOK);
        }
        else if (id == IDCANCEL) EndDialog(hDlg, IDCANCEL);
        break;
    }
    }
    return (INT_PTR)FALSE;
}

// ─── Unblock Password Dialog ──────────────────────────────────────────────────
struct UnblockPwData {
    std::wstring requiredHash;
    bool         correct;
};

INT_PTR CALLBACK UnblockPwDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static UnblockPwData* pData = NULL;
    switch (msg) {
    case WM_INITDIALOG:
        pData = (UnblockPwData*)lParam;
        pData->correct = false;
        CenterWindowOnScreen(hDlg);
        return (INT_PTR)TRUE;
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDOK) {
            wchar_t pw[128] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_UNBLOCK_PW, pw, 128);
            if (HashPassword(std::wstring(pw)) == pData->requiredHash) {
                pData->correct = true; EndDialog(hDlg, IDOK);
            } else {
                MessageBoxW(hDlg, L"Incorrect password.", L"Wrong Password", MB_ICONERROR);
                SetDlgItemTextW(hDlg, IDC_EDIT_UNBLOCK_PW, L"");
            }
        } else if (id == IDCANCEL) EndDialog(hDlg, IDCANCEL);
        break;
    }
    }
    return (INT_PTR)FALSE;
}

bool VerifyUnblock(HWND hParent, const std::wstring& hash)
{
    if (hash.empty()) return true;
    UnblockPwData data; data.requiredHash = hash; data.correct = false;
    DialogBoxParamW(g_hInst, MAKEINTRESOURCE(IDD_UNBLOCK_PW_DIALOG),
                   hParent, UnblockPwDlgProc, (LPARAM)&data);
    return data.correct;
}

// ─── Schedule Dialog ──────────────────────────────────────────────────────────
INT_PTR CALLBACK ScheduleDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG: {
        CenterWindowOnScreen(hDlg);
        CheckRadioButton(hDlg, IDC_RADIO_BLOCK_FW2, IDC_RADIO_BLOCK_BOTH2, IDC_RADIO_BLOCK_BOTH2);
        // Set custom format: show both date and time in one picker
        // DTM_SETFORMAT with "yyyy-MM-dd HH:mm" makes DTM_GETSYSTEMTIME fill all fields
        SendDlgItemMessageW(hDlg, IDC_DATETIME_START, DTM_SETFORMATW, 0, (LPARAM)L"yyyy'-'MM'-'dd HH':'mm':'ss");
        SendDlgItemMessageW(hDlg, IDC_DATETIME_END,   DTM_SETFORMATW, 0, (LPARAM)L"yyyy'-'MM'-'dd HH':'mm':'ss");
        SYSTEMTIME st; GetLocalTime(&st);
        SendDlgItemMessageW(hDlg, IDC_DATETIME_START, DTM_SETSYSTEMTIME, GDT_VALID, (LPARAM)&st);
        st.wHour = (st.wHour + 1) % 24;
        SendDlgItemMessageW(hDlg, IDC_DATETIME_END,   DTM_SETSYSTEMTIME, GDT_VALID, (LPARAM)&st);
        if (lParam) SetDlgItemTextW(hDlg, IDC_EDIT_SCHED_PATH, (const wchar_t*)lParam);
        return (INT_PTR)TRUE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_BTN_SCHED_BROWSE) {
            wchar_t szFile[MAX_PATH] = {0};
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hDlg;
            ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = szFile; ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) SetDlgItemTextW(hDlg, IDC_EDIT_SCHED_PATH, szFile);
        }
        else if (id == IDOK) {
            wchar_t szPath[MAX_PATH] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_SCHED_PATH, szPath, MAX_PATH);
            if (wcslen(szPath) == 0) {
                MessageBoxW(hDlg, L"Please select an EXE file.", L"Missing Path", MB_ICONERROR);
                return (INT_PTR)TRUE;
            }
            ScheduleEntry se;
            se.filePath  = szPath;
            se.fileName  = GetFileNameFromPath(se.filePath);
            se.triggered = false;
            se.ended     = false;
            if      (IsDlgButtonChecked(hDlg, IDC_RADIO_BLOCK_FW2)  == BST_CHECKED) se.blockType = BLOCK_FIREWALL;
            else if (IsDlgButtonChecked(hDlg, IDC_RADIO_BLOCK_RUN2) == BST_CHECKED) se.blockType = BLOCK_PROCESS;
            else                                                                      se.blockType = BLOCK_BOTH;
            // GDT_VALID=1 means the picker filled the SYSTEMTIME; fallback to now if not
            if (SendDlgItemMessageW(hDlg, IDC_DATETIME_START, DTM_GETSYSTEMTIME, 0, (LPARAM)&se.startTime) != GDT_VALID)
                GetLocalTime(&se.startTime);
            if (SendDlgItemMessageW(hDlg, IDC_DATETIME_END, DTM_GETSYSTEMTIME, 0, (LPARAM)&se.endTime) != GDT_VALID)
                GetLocalTime(&se.endTime);
            se.hasEnd = (CompareSysTime(se.endTime, se.startTime) > 0);
            wchar_t pw1[128] = {0}, pw2[128] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD,         pw1, 128);
            GetDlgItemTextW(hDlg, IDC_EDIT_PASSWORD_CONFIRM, pw2, 128);
            if (wcslen(pw1) > 0) {
                if (wcscmp(pw1, pw2) != 0) {
                    MessageBoxW(hDlg, L"Passwords do not match!", L"Error", MB_ICONERROR);
                    return (INT_PTR)TRUE;
                }
                se.passwordHash = HashPassword(std::wstring(pw1));
            } else {
                se.passwordHash = L"";
            }
            g_scheduleList.push_back(se);
            SaveScheduleList();
            // Register Windows Task for realtime operation (works even when FWBlock is closed)
            RegisterWindowsTask(g_scheduleList.size() - 1);
            EndDialog(hDlg, IDOK);
        }
        else if (id == IDCANCEL) EndDialog(hDlg, IDCANCEL);
        break;
    }
    }
    return (INT_PTR)FALSE;
}

// ─── Apply a block (used by both manual + scheduler) ─────────────────────────
void ApplyBlock(HWND hDlg, const std::wstring& path, int blockType, const std::wstring& pwHash)
{
    if (path.empty()) return;
    std::wstring fname    = GetFileNameFromPath(path);
    std::wstring ruleName = GetRuleNameFromPath(path);
    for (size_t i = 0; i < g_blockedList.size(); i++) {
        if (_wcsicmp(g_blockedList[i].filePath.c_str(), path.c_str()) == 0) return;
    }
    BlockedEntry entry;
    entry.filePath     = path;
    entry.fileName     = fname;
    entry.ruleName     = ruleName;
    entry.blockType    = blockType;
    entry.fwBlocked    = false;
    entry.procBlocked  = false;
    entry.passwordHash = pwHash;
    if (blockType & BLOCK_FIREWALL) entry.fwBlocked   = AddFirewallRule(path, ruleName);
    if (blockType & BLOCK_PROCESS)  entry.procBlocked = BlockProcessExecution(path, ruleName);
    g_blockedList.push_back(entry);
    SaveList();
    if (hDlg) {
        HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
        RefreshListView(hList, g_blockedList);
        SetStatus(hDlg, L"Blocked: " + fname);
    }
    // Tray notification
    ShowTrayNotification(L"FWBlock", L"Blocked: " + fname);
}

void RemoveBlock(HWND hDlg, size_t idx)
{
    if (idx >= g_blockedList.size()) return;
    BlockedEntry& e = g_blockedList[idx];
    if (e.fwBlocked)   RemoveFirewallRule(e.ruleName);
    if (e.procBlocked) UnblockProcessExecution(e.filePath, e.ruleName);
    std::wstring fname = e.fileName;
    g_blockedList.erase(g_blockedList.begin() + idx);
    SaveList();
    if (hDlg) {
        RefreshListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED), g_blockedList);
        UpdateBlockButtonLabels(hDlg);
        SetStatus(hDlg, L"Unblocked: " + fname);
    }
    ShowTrayNotification(L"FWBlock", L"Unblocked: " + fname);
}

// ─── Re-apply all saved blocks (called on silent startup after reboot) ────────
// Firewall rules and IFEO are lost after a reboot if not properly restored.
// This ensures all saved blocked entries are enforced again.
void ReapplyAllBlocks()
{
    for (size_t i = 0; i < g_blockedList.size(); i++) {
        BlockedEntry& e = g_blockedList[i];
        bool fwExists   = IsFirewallRuleExists(e.ruleName);
        bool procExists = IsProcessBlocked(e.filePath);
        bool changed    = false;
        if ((e.blockType & BLOCK_FIREWALL) && !fwExists) {
            e.fwBlocked = AddFirewallRule(e.filePath, e.ruleName);
            changed = true;
        }
        if ((e.blockType & BLOCK_PROCESS) && !procExists) {
            e.procBlocked = BlockProcessExecution(e.filePath, e.ruleName);
            changed = true;
        }
        if (changed)
            ShowTrayNotification(L"FWBlock", L"Re-applied block: " + e.fileName);
    }
    SaveList();
}

// ─── Scheduler tick (called by WM_TIMER) ─────────────────────────────────────
void CheckSchedules(HWND hDlg)
{
    SYSTEMTIME now; GetLocalTime(&now);
    bool changed = false;
    for (size_t i = 0; i < g_scheduleList.size(); i++) {
        ScheduleEntry& se = g_scheduleList[i];
        if (se.ended) continue;

        // If end time has already passed (even if start was never triggered), skip/expire
        if (se.hasEnd && CompareSysTime(now, se.endTime) >= 0 && !se.triggered) {
            // Schedule window already passed without being applied - just remove it
            se.ended = true;
            changed = true;
            continue;
        }

        if (!se.triggered && CompareSysTime(now, se.startTime) >= 0) {
            ApplyBlock(hDlg, se.filePath, se.blockType, se.passwordHash);
            se.triggered = true;
            changed = true;
        }
        if (se.triggered && !se.ended && se.hasEnd && CompareSysTime(now, se.endTime) >= 0) {
            for (size_t j = 0; j < g_blockedList.size(); j++) {
                if (_wcsicmp(g_blockedList[j].filePath.c_str(), se.filePath.c_str()) == 0) {
                    BlockedEntry& e = g_blockedList[j];
                    if (e.fwBlocked)   RemoveFirewallRule(e.ruleName);
                    if (e.procBlocked) UnblockProcessExecution(e.filePath, e.ruleName);
                    std::wstring fname = e.fileName;
                    g_blockedList.erase(g_blockedList.begin() + j);
                    SaveList();
                    if (hDlg) RefreshListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED), g_blockedList);
                    ShowTrayNotification(L"FWBlock Schedule", L"Auto-unblocked: " + fname);
                    break;
                }
            }
            se.ended = true;
            changed = true;
        }
    }

    // Remove all ended entries from the schedule list
    if (changed) {
        for (size_t i = g_scheduleList.size(); i-- > 0; ) {
            if (g_scheduleList[i].ended) {
                DeleteWindowsTask(i);
                g_scheduleList.erase(g_scheduleList.begin() + i);
            }
        }
        SaveScheduleList();
        if (hDlg) RefreshScheduleListView(GetDlgItem(hDlg, IDC_LIST_SCHEDULES));
    }
}

// ─── Handle /dotask command-line (called by Windows Scheduler) ────────────────
void HandleDoTask(const std::wstring& taskName)
{
    // Task name format: FWBlock_Sched_XXXX (start) or FWBlock_Sched_XXXX_end (end)
    std::wstring prefix(TASK_PREFIX);
    if (taskName.find(prefix) != 0) return;
    std::wstring rest   = taskName.substr(prefix.size()); // e.g. "0001" or "0001_end"
    bool isEnd          = (rest.size() > 4 && rest.substr(rest.size()-4) == L"_end");
    std::wstring idxStr = isEnd ? rest.substr(0, rest.size()-4) : rest;
    int idx             = _wtoi(idxStr.c_str());

    LoadScheduleList();
    LoadList();
    if (idx < 0 || idx >= (int)g_scheduleList.size()) return;
    ScheduleEntry& se = g_scheduleList[idx];

    if (!isEnd) {
        // Start: apply block
        if (!se.triggered) {
            ApplyBlock(NULL, se.filePath, se.blockType, se.passwordHash);
            se.triggered = true;
            SaveScheduleList();
        }
    } else {
        // End: remove block and mark done
        if (se.triggered && !se.ended) {
            for (size_t j = 0; j < g_blockedList.size(); j++) {
                if (_wcsicmp(g_blockedList[j].filePath.c_str(), se.filePath.c_str()) == 0) {
                    BlockedEntry& e = g_blockedList[j];
                    if (e.fwBlocked)   RemoveFirewallRule(e.ruleName);
                    if (e.procBlocked) UnblockProcessExecution(e.filePath, e.ruleName);
                    g_blockedList.erase(g_blockedList.begin() + j);
                    SaveList();
                    break;
                }
            }
            se.ended = true;
            SaveScheduleList();
        }
    }
}

// ─── Toggle selected item ─────────────────────────────────────────────────────
bool TryToggleSelected(HWND hDlg, int btnId)
{
    HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
    int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_blockedList.size()) return false;
    BlockedEntry& e = g_blockedList[sel];
    if (btnId == IDC_BTN_BLOCK_FW) {
        if (e.fwBlocked) {
            if (!VerifyUnblock(hDlg, e.passwordHash)) return true;
            RemoveFirewallRule(e.ruleName);
            e.fwBlocked = false;
            if (!e.procBlocked) { g_blockedList.erase(g_blockedList.begin() + sel); }
        } else {
            e.fwBlocked = AddFirewallRule(e.filePath, e.ruleName);
            e.blockType |= BLOCK_FIREWALL;
        }
    } else if (btnId == IDC_BTN_BLOCK_RUN) {
        if (e.procBlocked) {
            if (!VerifyUnblock(hDlg, e.passwordHash)) return true;
            UnblockProcessExecution(e.filePath, e.ruleName);
            e.procBlocked = false;
            if (!e.fwBlocked) { g_blockedList.erase(g_blockedList.begin() + sel); }
        } else {
            e.procBlocked = BlockProcessExecution(e.filePath, e.ruleName);
            e.blockType |= BLOCK_PROCESS;
        }
    } else if (btnId == IDC_BTN_BLOCK_BOTH) {
        bool bothBlocked = (e.fwBlocked && e.procBlocked);
        if (bothBlocked) {
            if (!VerifyUnblock(hDlg, e.passwordHash)) return true;
            RemoveFirewallRule(e.ruleName);
            UnblockProcessExecution(e.filePath, e.ruleName);
            g_blockedList.erase(g_blockedList.begin() + sel);
        } else {
            if (!e.fwBlocked)   e.fwBlocked   = AddFirewallRule(e.filePath, e.ruleName);
            if (!e.procBlocked) e.procBlocked  = BlockProcessExecution(e.filePath, e.ruleName);
            e.blockType = BLOCK_BOTH;
        }
    }
    SaveList();
    RefreshListView(hList, g_blockedList);
    UpdateBlockButtonLabels(hDlg);
    return true;
}

// ─── Fonts ────────────────────────────────────────────────────────────────────
static HFONT g_hFontTitle    = NULL;
static HFONT g_hFontSubtitle = NULL;
static HFONT g_hFontSection  = NULL;
static HFONT g_hFontUI       = NULL;
static HFONT g_hFontAboutTitle = NULL;
static HFONT g_hFontAboutSub   = NULL;

// ─── About Dialog ─────────────────────────────────────────────────────────────
INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG: {
        HICON hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_FIREWALLBLOCKER));
        SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
        if (!g_hFontAboutTitle) g_hFontAboutTitle = CreateFont(
            -18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        if (!g_hFontAboutSub) g_hFontAboutSub = CreateFont(
            -11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        if (g_hFontAboutTitle) SendDlgItemMessageW(hDlg, IDC_ABOUT_NAME, WM_SETFONT, (WPARAM)g_hFontAboutTitle, TRUE);
        if (g_hFontAboutSub)   SendDlgItemMessageW(hDlg, IDC_ABOUT_VER,  WM_SETFONT, (WPARAM)g_hFontAboutSub, TRUE);
        CenterWindowOnScreen(hDlg);
        return (INT_PTR)TRUE;
    }
    case WM_NOTIFY: {
        NMHDR* pnm = (NMHDR*)lParam;
        if (pnm->idFrom == IDC_ABOUT_LINK && pnm->code == NM_CLICK) {
            ShellExecuteW(NULL, L"open", ((NMLINK*)lParam)->item.szUrl, NULL, NULL, SW_SHOWNORMAL);
            return (INT_PTR)TRUE;
        }
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
            EndDialog(hDlg, LOWORD(wParam));
        break;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        if (GetDlgCtrlID((HWND)lParam) == IDC_ABOUT_NAME) {
            SetTextColor(hdc, RGB(0, 102, 204));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
        break;
    }
    }
    return (INT_PTR)FALSE;
}

// ─── Main Dialog ──────────────────────────────────────────────────────────────
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG: {
        HICON hIcon = LoadIcon(g_hInst, MAKEINTRESOURCE(IDI_FIREWALLBLOCKER));
        SendMessage(hDlg, WM_SETICON, ICON_BIG,   (LPARAM)hIcon);
        SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);

        g_hFontTitle = CreateFont(-20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_hFontSubtitle = CreateFont(-10, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_hFontSection = CreateFont(-9, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_hFontUI = CreateFont(-11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        if (g_hFontTitle)    SendDlgItemMessageW(hDlg, IDC_STATIC_TITLE, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);
        if (g_hFontSubtitle) SendDlgItemMessageW(hDlg, IDC_STATIC_SEP,   WM_SETFONT, (WPARAM)g_hFontSubtitle, TRUE);
        if (g_hFontSection)  SendDlgItemMessageW(hDlg, IDC_STATIC_LIST,  WM_SETFONT, (WPARAM)g_hFontSection, TRUE);

        int ctrlIds[] = {
            IDC_BTN_BROWSE, IDC_BTN_BLOCK_FW, IDC_BTN_BLOCK_RUN,
            IDC_BTN_BLOCK_BOTH, IDC_BTN_UNBLOCK, IDC_BTN_REFRESH,
            IDC_BTN_SCHEDULE, IDC_BTN_DEL_SCHEDULE,
            IDC_EDIT_PATH, IDC_STATIC_PATH, IDC_STATIC_STATUS
        };
        for (int i = 0; i < 11; i++) {
            HWND hCtrl = GetDlgItem(hDlg, ctrlIds[i]);
            if (hCtrl && g_hFontUI) SendMessage(hCtrl, WM_SETFONT, (WPARAM)g_hFontUI, TRUE);
        }

        HMENU hMenu = LoadMenuW(g_hInst, MAKEINTRESOURCE(IDR_MENU_MAIN));
        SetMenu(hDlg, hMenu);

        SetupListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED));
        SetupScheduleListView(GetDlgItem(hDlg, IDC_LIST_SCHEDULES));

        LoadList();
        LoadScheduleList();
        RefreshListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED), g_blockedList);
        RefreshScheduleListView(GetDlgItem(hDlg, IDC_LIST_SCHEDULES));

        CenterWindowOnScreen(hDlg);

        SetButtonIcon(hDlg, IDC_BTN_BLOCK_FW,   IDI_BTN_BLOCK_FW);
        SetButtonIcon(hDlg, IDC_BTN_BLOCK_RUN,  IDI_BTN_BLOCK_RUN);
        SetButtonIcon(hDlg, IDC_BTN_BLOCK_BOTH, IDI_BTN_BLOCK_BOTH);
        SetButtonIcon(hDlg, IDC_BTN_UNBLOCK,    IDI_BTN_UNBLOCK);
        SetButtonIcon(hDlg, IDC_BTN_REFRESH,    IDI_BTN_REFRESH);
        SetButtonIcon(hDlg, IDC_BTN_BROWSE,     IDI_BTN_BROWSE);

        if (!IsElevated())
            SetStatus(hDlg, L"WARNING: Requires Administrator - some features may fail.");
        else
            SetStatus(hDlg, L"FWBlock v2.1 ready  (Administrator).");

        // Add system tray icon
        AddTrayIcon(hDlg);

        // Re-apply all saved blocks (ensures blocks survive reboot)
        ReapplyAllBlocks();

        // Update "Start with Windows" checkmark
        UpdateAutostartMenuCheck(hDlg);

        // Start scheduler timer (1s realtime check)
        SetTimer(hDlg, TIMER_SCHEDULE_CHECK, SCHEDULE_CHECK_MS, NULL);
        CheckSchedules(hDlg);

        return (INT_PTR)TRUE;
    }

    case WM_TIMER:
        if (wParam == TIMER_SCHEDULE_CHECK) {
            CheckSchedules(hDlg);
        }
        break;

    case WM_TRAYICON: {
        if (lParam == WM_RBUTTONUP) {
            POINT pt; GetCursorPos(&pt);
            HMENU hTrayMenu = LoadMenuW(g_hInst, MAKEINTRESOURCEW(IDR_TRAY_MENU));
            if (hTrayMenu) {
                HMENU hPopup = GetSubMenu(hTrayMenu, 0);
                // Update checkmark for "Start with Windows"
                CheckMenuItem(hPopup, IDM_TRAY_AUTOSTART,
                              MF_BYCOMMAND | (IsAutostartEnabled() ? MF_CHECKED : MF_UNCHECKED));
                SetForegroundWindow(hDlg);
                TrackPopupMenu(hPopup, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hDlg, NULL);
                DestroyMenu(hTrayMenu);
            }
        } else if (lParam == WM_LBUTTONDBLCLK) {
            ShowWindow(hDlg, SW_SHOW);
            SetForegroundWindow(hDlg);
        }
        break;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);

        if (id == IDM_EXIT || id == IDM_TRAY_EXIT) {
            RemoveTrayIcon();
            DestroyWindow(hDlg);
        }
        else if (id == IDM_TRAY_SHOW) {
            ShowWindow(hDlg, SW_SHOW);
            SetForegroundWindow(hDlg);
        }
        else if (id == IDM_ABOUT) {
            DialogBoxW(g_hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hDlg, AboutDlgProc);
        }
        else if (id == IDM_AUTOSTART || id == IDM_TRAY_AUTOSTART) {
            ToggleAutostart();
            UpdateAutostartMenuCheck(hDlg);
            bool now = IsAutostartEnabled();
            ShowTrayNotification(L"FWBlock",
                now ? L"FWBlock will start automatically with Windows."
                    : L"FWBlock will no longer start with Windows.");
        }
        else if (id == IDC_BTN_REFRESH) {
            for (size_t i = 0; i < g_blockedList.size(); i++) {
                g_blockedList[i].fwBlocked   = IsFirewallRuleExists(g_blockedList[i].ruleName);
                g_blockedList[i].procBlocked = IsProcessBlocked(g_blockedList[i].filePath);
            }
            SaveList();
            RefreshListView(GetDlgItem(hDlg, IDC_LIST_BLOCKED), g_blockedList);
            RefreshScheduleListView(GetDlgItem(hDlg, IDC_LIST_SCHEDULES));
            UpdateBlockButtonLabels(hDlg);
            SetStatus(hDlg, L"List refreshed.");
        }
        else if (id == IDC_BTN_BROWSE) {
            wchar_t szFile[MAX_PATH] = {0};
            OPENFILENAMEW ofn = {0};
            ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hDlg;
            ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = szFile; ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            ofn.lpstrTitle = L"Select EXE file to block";
            if (GetOpenFileNameW(&ofn)) {
                SetDlgItemTextW(hDlg, IDC_EDIT_PATH, szFile);
                HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
                ListView_SetItemState(hList, -1, 0, LVIS_SELECTED);
                UpdateBlockButtonLabels(hDlg);
            }
        }
        else if (id == IDC_BTN_BLOCK_FW  ||
                 id == IDC_BTN_BLOCK_RUN ||
                 id == IDC_BTN_BLOCK_BOTH)
        {
            if (TryToggleSelected(hDlg, id)) break;
            wchar_t szPath[MAX_PATH] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_PATH, szPath, MAX_PATH);
            std::wstring path(szPath);
            if (path.empty()) {
                MessageBoxW(hDlg,
                    L"Select or type an EXE path first,\nor select an item in the list to toggle.",
                    L"No Target", MB_ICONINFORMATION);
                break;
            }
            DWORD attr = GetFileAttributesW(path.c_str());
            bool fileExists = (attr != INVALID_FILE_ATTRIBUTES);
            if (!fileExists && id != IDC_BTN_BLOCK_FW) {
                MessageBoxW(hDlg, L"File not found!\n\nBlock Running (IFEO) requires a valid EXE path.",
                            L"File Not Found", MB_ICONERROR);
                break;
            }
            if (!fileExists && id == IDC_BTN_BLOCK_FW) {
                if (MessageBoxW(hDlg, L"File not found. Continue adding firewall rule anyway?",
                                L"File Not Found", MB_YESNO | MB_ICONQUESTION) != IDYES) break;
            }
            std::wstring fname = GetFileNameFromPath(path);
            for (size_t i = 0; i < g_blockedList.size(); i++) {
                if (_wcsicmp(g_blockedList[i].filePath.c_str(), path.c_str()) == 0) {
                    MessageBoxW(hDlg, L"This file is already in the blocked list.\nSelect it in the list to toggle.",
                                L"Already Listed", MB_ICONINFORMATION);
                    goto done;
                }
            }
            {
                PasswordDlgData pwData;
                INT_PTR pwResult = DialogBoxParamW(g_hInst, MAKEINTRESOURCE(IDD_PASSWORD_DIALOG),
                                                   hDlg, PasswordDlgProc, (LPARAM)&pwData);
                if (pwResult != IDOK) break;
                int blockType = (id == IDC_BTN_BLOCK_FW)   ? BLOCK_FIREWALL :
                                (id == IDC_BTN_BLOCK_RUN)  ? BLOCK_PROCESS  : BLOCK_BOTH;
                ApplyBlock(hDlg, path, blockType, pwData.outHash);
                SetStatus(hDlg, L"Blocked: " + fname +
                          (pwData.outHash.empty() ? L"" : L" (password protected)"));
            }
            done:;
        }
        else if (id == IDC_BTN_UNBLOCK) {
            HWND hList = GetDlgItem(hDlg, IDC_LIST_BLOCKED);
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= (int)g_blockedList.size()) {
                MessageBoxW(hDlg, L"Select an item in the list first.",
                            L"Nothing Selected", MB_ICONINFORMATION);
                break;
            }
            BlockedEntry& e = g_blockedList[sel];
            if (!VerifyUnblock(hDlg, e.passwordHash)) break;
            int r = MessageBoxW(hDlg,
                (L"Unblock:\n" + e.filePath + L"\n\nContinue?").c_str(),
                L"Confirm Unblock", MB_YESNO | MB_ICONQUESTION);
            if (r != IDYES) break;
            RemoveBlock(hDlg, (size_t)sel);
        }
        else if (id == IDC_BTN_SCHEDULE) {
            wchar_t szPath[MAX_PATH] = {0};
            GetDlgItemTextW(hDlg, IDC_EDIT_PATH, szPath, MAX_PATH);
            INT_PTR res = DialogBoxParamW(g_hInst, MAKEINTRESOURCE(IDD_SCHEDULE_DIALOG),
                                          hDlg, ScheduleDlgProc, (LPARAM)(szPath[0] ? szPath : NULL));
            if (res == IDOK) {
                RefreshScheduleListView(GetDlgItem(hDlg, IDC_LIST_SCHEDULES));
                SetStatus(hDlg, L"Schedule added (Windows Task registered for realtime).");
                CheckSchedules(hDlg);
            }
        }
        else if (id == IDC_BTN_DEL_SCHEDULE) {
            HWND hSList = GetDlgItem(hDlg, IDC_LIST_SCHEDULES);
            int sel = ListView_GetNextItem(hSList, -1, LVNI_SELECTED);
            if (sel < 0 || sel >= (int)g_scheduleList.size()) {
                MessageBoxW(hDlg, L"Select a scheduled entry to delete.",
                            L"Nothing Selected", MB_ICONINFORMATION);
                break;
            }
            ScheduleEntry& se = g_scheduleList[sel];
            if (!VerifyUnblock(hDlg, se.passwordHash)) break;
            DeleteWindowsTask((size_t)sel);
            g_scheduleList.erase(g_scheduleList.begin() + sel);
            SaveScheduleList();
            RefreshScheduleListView(hSList);
            SetStatus(hDlg, L"Schedule deleted.");
        }
        break;
    }

    case WM_NOTIFY: {
        NMHDR* pNMHDR = (NMHDR*)lParam;
        if (pNMHDR->idFrom == IDC_LIST_BLOCKED && pNMHDR->code == LVN_ITEMCHANGED) {
            UpdateBlockButtonLabels(hDlg);
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        int ctlId = GetDlgCtrlID((HWND)lParam);
        if (ctlId == IDC_STATIC_TITLE) {
            SetTextColor(hdc, RGB(0, 102, 204));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
        if (ctlId == IDC_STATIC_SEP || ctlId == IDC_STATIC_LIST || ctlId == IDC_STATIC_SCHED_LIST) {
            SetTextColor(hdc, RGB(100, 100, 100));
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetStockObject(NULL_BRUSH);
        }
        return (INT_PTR)FALSE;
    }

    // Minimize to tray instead of closing
    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_MINIMIZE) {
            ShowWindow(hDlg, SW_HIDE);
            ShowTrayNotification(L"FWBlock", L"FWBlock is running in the system tray.");
            return (INT_PTR)TRUE;
        }
        break;

    case WM_CLOSE:
        // Minimize to tray on X button
        ShowWindow(hDlg, SW_HIDE);
        ShowTrayNotification(L"FWBlock", L"FWBlock is still running. Right-click tray icon to exit.");
        return (INT_PTR)TRUE;

    case WM_DESTROY:
        KillTimer(hDlg, TIMER_SCHEDULE_CHECK);
        RemoveTrayIcon();
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
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int)
{
    g_hInst = hInstance;

    // Handle /dotask and /dotask-end commands from Windows Scheduler (no UI needed)
    if (lpCmdLine && wcsncmp(lpCmdLine, L"/dotask ", 8) == 0) {
        std::wstring taskName = lpCmdLine + 8;
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        HandleDoTask(taskName);
        CoUninitialize();
        return 0;
    }
    if (lpCmdLine && wcsncmp(lpCmdLine, L"/dotask-end ", 12) == 0) {
        std::wstring taskName = lpCmdLine + 12;
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        HandleDoTask(taskName + L"_end"); // reuse HandleDoTask with _end suffix
        CoUninitialize();
        return 0;
    }

    if (!IsElevated()) { RelaunchAsAdmin(); return 0; }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_LISTVIEW_CLASSES | ICC_WIN95_CLASSES | ICC_DATE_CLASSES;
    InitCommonControlsEx(&icc);

    // Determine if we were launched silently (autostart on boot)
    bool silentMode = (lpCmdLine && wcscmp(lpCmdLine, L"/silent") == 0);

    HWND hDlg = CreateDialogW(hInstance,
                               MAKEINTRESOURCE(IDD_FIREWALLBLOCKER_DIALOG),
                               NULL, MainDlgProc);

    if (silentMode) {
        // Stay hidden in tray; re-apply all saved blocks in case they were lost on reboot
        ShowWindow(hDlg, SW_HIDE);
    } else {
        ShowWindow(hDlg, SW_SHOW);
        UpdateWindow(hDlg);
    }

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
