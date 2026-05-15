// =============================================================================
//  FirewallBlocker.h
// =============================================================================
//  Author      : Ari Sohandri Putra
//  Repository  : https://github.com/arisohandriputra/FWBlock
// =============================================================================
#pragma once
#include "resource.h"
#include <string>
#include <vector>

// Block type flags
#define BLOCK_FIREWALL  0x01
#define BLOCK_PROCESS   0x02
#define BLOCK_BOTH      0x03

// Timer ID for schedule checker
#define TIMER_SCHEDULE_CHECK  9001
#define SCHEDULE_CHECK_MS     1000    // check every 1 second (realtime precision)

// Simple password hash (FNV-1a 32-bit) stored as hex string
std::wstring HashPassword(const std::wstring& pw);

struct BlockedEntry {
    std::wstring filePath;
    std::wstring fileName;
    std::wstring ruleName;
    int          blockType;
    bool         fwBlocked;
    bool         procBlocked;
    std::wstring passwordHash;  // empty = no password
};

struct ScheduleEntry {
    std::wstring filePath;
    std::wstring fileName;
    int          blockType;
    SYSTEMTIME   startTime;
    SYSTEMTIME   endTime;
    bool         hasEnd;        // false = block forever once triggered
    bool         triggered;     // has the block been applied?
    bool         ended;         // has the unblock been applied?
    std::wstring passwordHash;
};

// Forward declarations
INT_PTR CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK PasswordDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK UnblockPwDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK ScheduleDlgProc(HWND, UINT, WPARAM, LPARAM);

// Utility
std::wstring GetFileNameFromPath(const std::wstring& path);
std::wstring GetRuleNameFromPath(const std::wstring& path);

// Firewall
bool AddFirewallRule(const std::wstring& exePath, const std::wstring& ruleName);
bool RemoveFirewallRule(const std::wstring& ruleName);
bool IsFirewallRuleExists(const std::wstring& ruleName);

// Process block
bool BlockProcessExecution(const std::wstring& exePath, const std::wstring& ruleName);
bool UnblockProcessExecution(const std::wstring& exePath, const std::wstring& ruleName);

// List helpers
void RefreshListView(HWND hList, const std::vector<BlockedEntry>& entries);
void SetStatus(HWND hDlg, const std::wstring& msg);

// Autostart
bool IsAutostartEnabled();
void SetAutostart(bool enable);
void ToggleAutostart();
void UpdateAutostartMenuCheck(HWND hDlg);

// Startup restore
void ReapplyAllBlocks();

// Globals
extern std::vector<BlockedEntry>  g_blockedList;
extern std::vector<ScheduleEntry> g_scheduleList;
extern HINSTANCE g_hInst;
