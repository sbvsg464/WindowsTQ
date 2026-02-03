// SYSTEM.h
#pragma once

#include "lib.h"
#include "token.h"

void privilegeEscalationForTI() {//已确认，是trustedinstaller
    system("cls");
    std::cout << "[+] 正在尝试以trustedinstaller权限弹出cmd.exe，请稍候（弹出窗口后，可输入whoami /groups | findstr Trusted来检测所有者，返回NT SERVICE\\TrustedInstaller即为有trustedinstaller权限）...\n";
    system("powershell -NoProfile -ExecutionPolicy Bypass -Command \"Install-Module -Name NtObjectManager -Force -Scope CurrentUser; Import-Module NtObjectManager; sc.exe start TrustedInstaller; Set-NtTokenPrivilege SeDebugPrivilege; $p = Get-NtProcess -Name TrustedInstaller.exe; New-Win32Process cmd.exe -CreationFlags NewConsole -ParentProcess $p\"");
    std::cout << "[+] 操作完成，按任意键返回主菜单...\n";
    system("pause");
}

bool elevateProcess() {//提升为管理员权限(没有绕过UAC)
    WCHAR exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        return false;
    }
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = GetCommandLineW();
    sei.nShow = SW_NORMAL;
    sei.fMask = SEE_MASK_NO_CONSOLE;
    if (!ShellExecuteExW(&sei)) {
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            MessageBoxW(nullptr, L"用户取消了提权请求", L"提示", MB_ICONWARNING | MB_OK);
        }
        return false;
    }
    return true;
}

bool EnablePrivilege(LPCTSTR privilegeName) {//开启调试
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result && (GetLastError() == ERROR_SUCCESS);
}

// 检查是否为纯 SYSTEM（是 SYSTEM 但不包含 TrustedInstaller 组）
bool IsPureSystemProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    HANDLE hToken = NULL;
    bool isPureSystem = false;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        // 检查是否为 SYSTEM (S-1-5-18)
        DWORD len = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
        std::vector<BYTE> buffer(len);
        if (GetTokenInformation(hToken, TokenUser, buffer.data(), len, &len)) {
            PTOKEN_USER pUser = (PTOKEN_USER)buffer.data();
            if (IsWellKnownSid(pUser->User.Sid, WinLocalSystemSid)) {
                // 是 SYSTEM，现在检查组中是否有 TrustedInstaller (S-1-5-80-...)
                GetTokenInformation(hToken, TokenGroups, NULL, 0, &len);
                buffer.resize(len);
                if (GetTokenInformation(hToken, TokenGroups, buffer.data(), len, &len)) {
                    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)buffer.data();
                    bool hasTI = false;
                    for (DWORD i = 0; i < pGroups->GroupCount; i++) {
                        LPSTR sidStr = NULL;
                        if (ConvertSidToStringSidA(pGroups->Groups[i].Sid, &sidStr)) {
                            if (strncmp(sidStr, "S-1-5-80-", 9) == 0) {
                                hasTI = true;
                                LocalFree(sidStr);
                                break;
                            }
                            LocalFree(sidStr);
                        }
                    }
                    // 是 SYSTEM 且没有 TI 组 = 纯 SYSTEM
                    isPureSystem = !hasTI;
                }
            }
        }
        CloseHandle(hToken);
    }
    CloseHandle(hProcess);
    return isPureSystem;
}

// 获取 services.exe 的 PID（通常是纯 SYSTEM）
DWORD FindPureSystemProcess() {
    DWORD processes[1024], cbNeeded;
    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
        return 0;
    for (unsigned i = 0; i < cbNeeded / sizeof(DWORD); i++) {
        if (processes[i] == 0) continue;
        // 打开进程查询名称
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (!hProcess) continue;
        WCHAR szProcessName[MAX_PATH] = L"<unknown>";
        HMODULE hMod;
        DWORD cbNeededMod;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeededMod)) {
            GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName)/sizeof(WCHAR));
            // 优先查找 services.exe（纯 SYSTEM 且稳定存在）
            if (_wcsicmp(szProcessName, L"services.exe") == 0) {
                if (IsPureSystemProcess(processes[i])) {
                    CloseHandle(hProcess);
                    return processes[i];
                }
            }
            // 备选：wininit.exe, winlogon.exe
            else if ((_wcsicmp(szProcessName, L"wininit.exe") == 0 ||
                     _wcsicmp(szProcessName, L"winlogon.exe") == 0) && 
                     IsPureSystemProcess(processes[i])) {
                CloseHandle(hProcess);
                return processes[i];
            }
        }
        CloseHandle(hProcess);
    }
    return 0;
}

bool RunAsPureSystem() {
    system("pause");
    // 必须启用调试权限才能打开 SYSTEM 进程
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        std::cerr << "[-] 启用 SeDebugPrivilege 失败\n";
        return false;
    }
    EnablePrivilege(SE_DEBUG_NAME);              // 打开进程
    EnablePrivilege(SE_IMPERSONATE_NAME);        // 模拟（备用方案需要）
    EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    DWORD pid = FindPureSystemProcess();
    if (pid == 0) {
        std::cerr << "[-] 未找到纯 SYSTEM 进程\n";
        return false;
    }
    std::cout << "[+] 找到纯净的 SYSTEM 进程 PID: " << pid << "\n";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] OpenProcess 失败: " << GetLastError() << "\n";
        return false;
    }
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        std::cerr << "[-] OpenProcessToken 失败: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        std::cerr << "[-] DuplicateTokenEx 失败: " << GetLastError() << "\n";
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }
    // 设置 Session ID
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId != 0xFFFFFFFF) {
        SetTokenInformation(hDupToken, TokenSessionId, &sessionId, sizeof(sessionId));
    }
    // 使用纯 SYSTEM 令牌创建进程
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    std::wstring cmd = L"cmd.exe /k \"whoami /user && echo 检查是否有TI组:&whoami /groups | findstr Trusted && echo [如果有TI则说明不是SYSTEM]&pause\"";
    BOOL success = CreateProcessAsUserW(
        hDupToken, 
        NULL, 
        &cmd[0], 
        NULL, NULL, 
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, 
        NULL, 
        NULL, 
        &si, 
        &pi
    );
    if (!success) {
        std::cerr << "[-] CreateProcessAsUserW 失败: " << GetLastError() << "\n";
    } else {
        std::cout << "[+] 成功创建纯 SYSTEM 进程，PID: " << pi.dwProcessId << "\n";
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return success;
}

void beforeRunAsSystem() {
    system("cls");
    std::cout << "[+] 请稍等\n";
    if (IsTrustedInstaller()) {
        std::cout << "[*] 当前已经是trustedinstaller权限\n";
        RunAsPureSystem();
        return;
    } else {
        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);
        std::string psCmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
            "Install-Module -Name NtObjectManager -Force -Scope CurrentUser -ErrorAction SilentlyContinue; "
            "Import-Module NtObjectManager; "
            "sc.exe start TrustedInstaller; "
            "Set-NtTokenPrivilege SeDebugPrivilege; "
            "$p = Get-NtProcess -Name TrustedInstaller.exe; "
            "New-Win32Process '" + std::string(currentPath) + "' -CreationFlags NewConsole -ParentProcess $p"
            "\"";
        std::cout << "[*] 正在以trustedinstaller权限重新启动本程序以获取SYSTEM权限，弹出窗口后再次选择选项4来继续操作...\n";
        system(psCmd.c_str());
    }
}
