// =============================================================================
//  resource.h
// =============================================================================
//
//  FirewallBlocker Resource Definitions
//
//  Author      : Ari Sohandri Putra
//  Repository  : https://github.com/arisohandriputra/FWBlock
//
//  Description :
//  This file contains all resource identifiers used by the
//  FirewallBlocker application. These IDs are used to connect
//  Win32 resources such as dialogs, menus, icons, buttons,
//  static texts, and controls with the application source code.
//
//  Each numeric identifier represents a specific GUI component
//  or application resource that can be referenced inside the
//  Win32 API message handling system.
//
//  Main Components :
//  - Application icons
//  - Main window resources
//  - Menu resources
//  - Dialog resources
//  - Buttons and controls
//  - List boxes and status labels
//  - About dialog elements
//
//  This file is automatically included by the application and
//  works together with the resource script (.rc) file.
//
// =============================================================================
#define IDC_MYICON                      2
#define IDD_FIREWALLBLOCKER_DIALOG      102
#define IDS_APP_TITLE                   103
#define IDD_ABOUTBOX                    104
#define IDM_ABOUT                       105
#define IDM_EXIT                        106
#define IDI_FIREWALLBLOCKER             107
#define IDI_SMALL                       108
#define IDC_FIREWALLBLOCKER             109
#define IDR_MAINFRAME                   128
#define IDR_MENU_MAIN                   129
#define IDC_EDIT_PATH                   1001
#define IDC_BTN_BROWSE                  1002
#define IDC_BTN_BLOCK_FW                1003
#define IDC_BTN_BLOCK_RUN               1004
#define IDC_BTN_UNBLOCK                 1005
#define IDC_BTN_REFRESH                 1006
#define IDC_LIST_BLOCKED                1007
#define IDC_STATIC_STATUS               1008
#define IDC_STATIC_PATH                 1009
#define IDC_STATIC_LIST                 1010
#define IDC_BTN_BLOCK_BOTH              1011
#define IDC_STATIC_TITLE                1012
#define IDC_STATIC_SEP                  1013
#define IDC_ABOUT_NAME                  2001
#define IDC_ABOUT_VER                   2002
#define IDC_ABOUT_DESC                  2003
#define IDC_ABOUT_LINK                  2004

// Button icon resources
#define IDI_BTN_BLOCK_FW                3001
#define IDI_BTN_BLOCK_RUN               3002
#define IDI_BTN_BLOCK_BOTH              3003
#define IDI_BTN_UNBLOCK                 3004
#define IDI_BTN_REFRESH                 3005
#define IDI_BTN_BROWSE                  3006
#ifndef IDC_STATIC
#define IDC_STATIC (-1)
#endif
