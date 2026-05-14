// =============================================================================
//  FirewallBlocker.h
// =============================================================================
//
//  FirewallBlocker Main Header File
//
//  Author      : Ari Sohandri Putra
//  Repository  : https://github.com/arisohandriputra/FWBlock
//
//  Description :
//  This header file contains the main declarations, structures,
//  constants, and function prototypes used throughout the
//  FirewallBlocker application.
//
//  The file serves as the central configuration and interface
//  layer between the application's source modules, including
//  firewall management, process execution blocking, utility
//  helpers, and Win32 GUI handling.
//
//  Main Responsibilities :
//  - Define application block type flags
//  - Store blocked application information
//  - Declare firewall management functions
//  - Declare process restriction functions
//  - Provide utility helper declarations
//  - Manage blocked application list access
//
//  Blocking System :
//  FirewallBlocker supports multiple blocking methods:
//
//      BLOCK_FIREWALL
//          Blocks internet/network access using
//          Windows Firewall rules.
//
//      BLOCK_PROCESS
//          Prevents executable files from running
//          using system-level process restrictions.
//
//      BLOCK_BOTH
//          Combines firewall and process blocking
//          simultaneously.
//
//  BlockedEntry Structure :
//  The `BlockedEntry` structure stores all required
//  information related to blocked applications,
//  including:
//
//      - Full executable path
//      - File name
//      - Firewall rule name
//      - Blocking mode
//      - Firewall block state
//      - Process block state
//
//  Utility Functions :
//  Helper functions are used to:
//
//      - Extract file names from paths
//      - Generate firewall rule names
//      - Refresh list view controls
//      - Update application status text
//
//  Firewall Management :
//  The firewall functions interact directly with the
//  Windows Firewall COM API to create, remove, and
//  validate firewall rules dynamically.
//
//  Process Restriction :
//  Process blocking functions handle executable
//  restrictions using Windows security and registry
//  mechanisms such as IFEO or related methods.
//
//  Global Variables :
//  The global vector `g_blockedList` stores all
//  currently managed blocked applications during
//  runtime.
//
// =============================================================================
#pragma once

#include "resource.h"
#include <string>
#include <vector>

// Block type flags
#define BLOCK_FIREWALL  0x01
#define BLOCK_PROCESS   0x02
#define BLOCK_BOTH      0x03

struct BlockedEntry {
    std::wstring filePath;
    std::wstring fileName;
    std::wstring ruleName;
    int          blockType;   // BLOCK_FIREWALL | BLOCK_PROCESS | BLOCK_BOTH
    bool         fwBlocked;
    bool         procBlocked;
};

// Forward declarations
INT_PTR CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);

// Utility functions
std::wstring GetFileNameFromPath(const std::wstring& path);
std::wstring GetRuleNameFromPath(const std::wstring& path);

// Firewall functions
bool AddFirewallRule(const std::wstring& exePath, const std::wstring& ruleName);
bool RemoveFirewallRule(const std::wstring& ruleName);
bool IsFirewallRuleExists(const std::wstring& ruleName);

// Process block functions (AppLocker / Job Object)
bool BlockProcessExecution(const std::wstring& exePath, const std::wstring& ruleName);
bool UnblockProcessExecution(const std::wstring& exePath, const std::wstring& ruleName);

// List/View helpers
void RefreshListView(HWND hList, const std::vector<BlockedEntry>& entries);
void SetStatus(HWND hDlg, const std::wstring& msg);

// Global blocked list
extern std::vector<BlockedEntry> g_blockedList;
