#include <iostream>
#include <fstream>
#include <filesystem>
#include <format>
#include <vector>
#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include <psapi.h>
#include <lm.h>
#include <Aclapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "netapi32.lib")

/*
    注意!
    编译指令被更改，请参见V3.0 release发布页面
    否则报错!!!
*/

bool IsRunAsAdmin() {//检测是否为管理员
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 
        0, 0, 0, 0, 0, 0,
        &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}


void changePowershellPolicy() {//更改powershell执行策略
    system("cls");
    std::cout << "请选择你想要更改的PowerShell执行策略类型：\n1.Restricted(禁止所有 .ps1 脚本)\n2.AllSigned(所有脚本都必须数字签名)\n3.RemoteSigned(本地脚本可直接运行，网络脚本必须签名)\n4.Unrestricted(允许所有脚本运行，但第一次提示)\n5.Bypass(不阻止任何脚本运行)\n6.check(查看当前powershell策略)\n";
    char choice;
    std::cin >> choice;
    switch (choice) {
        case '1':
            system("powershell -Command \"Set-ExecutionPolicy Restricted -Scope LocalMachine\"");
            break;
        case '2':
            system("powershell -Command \"Set-ExecutionPolicy AllSigned -Scope LocalMachine\"");
            break;
        case '3':
            system("powershell -Command \"Set-ExecutionPolicy RemoteSigned -Scope LocalMachine\"");
            break;
        case '4':
            system("powershell -Command \"Set-ExecutionPolicy Unrestricted -Scope LocalMachine\"");
            break;
        case '5':
            system("powershell -Command \"Set-ExecutionPolicy Bypass -Scope LocalMachine\"");
            break;
        case '6':
            system("powershell -Command \"Get-ExecutionPolicy -List\"");
            break;
        default:
            std::cout << "未知命令\n";
            break;
    }
    std::cout << "[+] 操作完成，按任意键返回主菜单...\n";
    system("pause");
}

void WriteRegFile() {//写入注册表文件以实现右键接管文件功能
    system("cls");
    std::ofstream reg("ti.reg", std::ios::binary);//这个就是内容
    reg <<
    R"(Windows Registry Editor Version 5.00

    [HKEY_CLASSES_ROOT\*\shell\runas]
    @="管理员接管（Take Ownership）"

    [HKEY_CLASSES_ROOT\*\shell\runas\command]
    @="cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F"
    "IsolatedCommand"="cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F"

    [HKEY_CLASSES_ROOT\Directory\shell\runas]
    @="管理员接管（Take Ownership）"
    "NoWorkingDirectory"=""

    [HKEY_CLASSES_ROOT\Directory\shell\runas\command]
    @="cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t"
    "IsolatedCommand"="cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t"
    )"
    ;
    reg.close();
    system("reg import ti.reg");
    std::filesystem::remove("ti.reg");
    std::cout << "[+] 操作完成，按任意键返回主菜单...\n现在，右键一个文件，你将会看见一个“管理员接管（Take Ownership）”的选项，点击它即可将该文件的所有权和完全控制权限赋予administrator组\n";
    system("pause");
}

#ifndef SE_DEBUG_NAME
#define SE_DEBUG_NAME TEXT("SeDebugPrivilege")
#endif
#ifndef SE_ASSIGNPRIMARYTOKEN_NAME
#define SE_ASSIGNPRIMARYTOKEN_NAME TEXT("SeAssignPrimaryTokenPrivilege")
#endif
#ifndef SE_IMPERSONATE_NAME
#define SE_IMPERSONATE_NAME TEXT("SeImpersonatePrivilege")
#endif

void privilegeEscalationForTI() {//已确认，是trustedinstaller
    system("cls");
    std::cout << "[+] 正在尝试以trustedinstaller权限弹出cmd.exe，请稍候（弹出窗口后，可输入whoami /groups | findstr Trusted来检测所有者，返回NT SERVICE\\TrustedInstaller即为有trustedinstaller权限）...\n";
    system("powershell -NoProfile -ExecutionPolicy Bypass -Command \"Install-Module -Name NtObjectManager -Force -Scope CurrentUser; Import-Module NtObjectManager; sc.exe start TrustedInstaller; Set-NtTokenPrivilege SeDebugPrivilege; $p = Get-NtProcess -Name TrustedInstaller.exe; New-Win32Process cmd.exe -CreationFlags NewConsole -ParentProcess $p\"");
    std::cout << "[+] 操作完成，按任意键返回主菜单...\n";
    system("pause");
}

bool IsSystem() {//检测是否为system权限
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_USER pTokenUser = NULL;
    bool result = false;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return false;
    }
    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return false;
    }
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
        if (IsWellKnownSid(pTokenUser->User.Sid, WinLocalSystemSid)) {
            result = true;
        }
    }
    LocalFree(pTokenUser);
    CloseHandle(hToken);
    return result;
}

bool IsTrustedInstaller() {//检测是否为trustedinstaller权限
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;
    DWORD len = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &len);
    std::vector<BYTE> buffer(len);
    bool result = false;
    if (GetTokenInformation(hToken, TokenGroups, buffer.data(), len, &len)) {
        PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)buffer.data();
        for (DWORD i = 0; i < pGroups->GroupCount; i++) {
            LPSTR sidStr = NULL;
            if (ConvertSidToStringSidA(pGroups->Groups[i].Sid, &sidStr)) {
                if (strncmp(sidStr, "S-1-5-80-956008885", 18) == 0) {
                    result = true;
                    LocalFree(sidStr);
                    break;
                }
                LocalFree(sidStr);
            }
        }
    }
    
    CloseHandle(hToken);
    return result;
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

void beforeRunAsSystem() {//先让程序有trustedinstaller权限再启动SYSTEM cmd
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

bool IsAdministratorDisabled() {//检测Administrator是否被禁用
    LPUSER_INFO_4 info = nullptr;
    if (NetUserGetInfo(nullptr, L"Administrator", 4, (LPBYTE*)&info) != NERR_Success)
        return true;
    bool disabled = info->usri4_flags & UF_ACCOUNTDISABLE;
    NetApiBufferFree(info);
    return disabled;
}

bool SetAdministratorPassword(const std::wstring& password) {//给Administrator设置密码
    USER_INFO_1003 info{};
    info.usri1003_password = const_cast<LPWSTR>(password.c_str());
    DWORD err = 0;
    NET_API_STATUS status = NetUserSetInfo(
        nullptr,
        L"Administrator",
        1003,
        (LPBYTE)&info,
        &err
    );
    return status == NERR_Success;
}

bool EnableAdministrator() {//启用Administrator
    USER_INFO_1008 info{};
    info.usri1008_flags = UF_SCRIPT; // 不包含 UF_ACCOUNTDISABLE

    DWORD err = 0;
    NET_API_STATUS status = NetUserSetInfo(
        nullptr,
        L"Administrator",
        1008,
        (LPBYTE)&info,
        &err
    );
    return status == NERR_Success;
}

std::wstring ReadPasswordMasked() {//密码隐藏
    std::wstring password;
    wchar_t ch;
    while ((ch = _getwch()) != L'\r') {
        if (ch == L'\b') {
            if (!password.empty()) {
                password.pop_back();
                std::wcout << L"\b \b";
            }
        } else {
            password.push_back(ch);
            std::wcout << L"#";
        }
    }
    std::wcout << L"\n";
    return password;
}

PSID GetCurrentUserSid() {//获取当前用户的sid
    HANDLE token = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);

    PTOKEN_USER user =
        (PTOKEN_USER)malloc(size);

    GetTokenInformation(token, TokenUser, user, size, &size);

    CloseHandle(token);
    return user->User.Sid; // 注意：不要 free
}

bool GrantFullControlToCurrentUser(const std::wstring& path) {//授予完全控制权限
    PSID userSid = GetCurrentUserSid();
    if (!userSid) return false;
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPWSTR)userSid;
    PACL oldDacl = nullptr;
    PACL newDacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD res = GetNamedSecurityInfoW(
        path.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &oldDacl,
        nullptr,
        &sd
    );
    if (res != ERROR_SUCCESS)
        return false;
    res = SetEntriesInAclW(1, &ea, oldDacl, &newDacl);
    if (res != ERROR_SUCCESS)
        return false;
    res = SetNamedSecurityInfoW(
        (LPWSTR)path.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        newDacl,
        nullptr
    );
    if (sd) LocalFree(sd);
    if (newDacl) LocalFree(newDacl);
    return res == ERROR_SUCCESS;
}

void helpCenter() {//帮助中心
    system("cls");
    std::cout << "帮助中心(介绍什么时候他们有用):\n"
    "1.更改PowerShell执行策略: 想执行ps1的时候被拦截，不是你自己代码的问题!\n"
    "2.获取以administrator接管文件/文件夹功能: 使Administrator是文件夹的拥有者，搭配功能8可以让当前用户获取对文件夹的完全控制权限\n"
    "3.获取有trustedinstaller权限的cmd: 执行操作被trustedinstaller拦截的时候，比如格式化System32\n"
    "4.获取有SYSTEM权限的cmd: 以SYSTEM权限打开一个命令提示符窗口: 执行操作被SYSTEM拦截的时候，比如格式化ProgramData\n"
    "5.检查当前程序权限: 帮助用户检查是否拥有Administrator、trustedinstaller或SYSTEM权限\n"
    "6.将本程序提权为trustedinstaller: 将当前程序提升为trustedinstaller权限\n"
    "7.强开Administrator账户(支持Windows 10/11 Home): 在Windows 7 8 8.x 10 11中Administrator默认禁用状态(不是Administrator权限被禁用，是Administrator这个账户被禁用)\n"
    "8.让此账户获取指定文件夹的完全控制权限: 赋予此账户对指定文件夹的完全控制权限(如果操作失败，可以搭配功能2使用)\n"
    "e.exit: 退出程序\n"
    "h.help: 显示此帮助信息\n";
    std::cout << "[+] 操作完成，按任意键返回主菜单...\n";
    system("pause");
}

int main(int argc, char* argv[]) {
    system("chcp 65001 > nul");
    if (!IsRunAsAdmin()) {
        MessageBoxW(nullptr, L"正在尝试申请Administrator权限", L"权限不足", MB_ICONINFORMATION | MB_OK);
        if (elevateProcess()) {
            MessageBoxW(nullptr, L"申请Administrator权限成功\n请在新弹窗里操作！\n点击这个弹窗的任何部分都将关闭两个窗口！", L"提示", MB_ICONINFORMATION | MB_OK);
            return 0;
        }
        else {
            MessageBoxW(nullptr, L"申请Administrator权限失败，请尝试手动给予Administrator权限", L"失败", MB_ICONERROR | MB_OK);
            return 1;
        }
    }
h:
    system("cls");
    std::cout << "欢迎!版本:4.0 release\n请选择你想要的提权操作:\n"
    "1.更改PowerShell执行策略\n2.获取以administrator接管文件/文件夹功能\n3.获取有trustedinstaller权限的cmd\n"
    "4.获取有SYSTEM权限的cmd\n5.检查当前程序权限\n6.将本程序提权为trustedinstaller\n7.强开Administrator账户(支持Windows 10/11 Home)\n"
    "8.让此账户获取指定文件夹的完全控制权限\ne.exit\nh.help\n";
    char option;
    std::cin >> option;
    switch (option) {
        case '1':
            changePowershellPolicy();
            break;
        case '2':
            WriteRegFile();
            break;
        case '3':
            privilegeEscalationForTI();
            std::cout << "[+]如果启动成功，在新窗口输入whoami /groups | findstr Trusted\n有 NT SERVICE\\TrustedInstaller 行，说明成功获取了trustedinstaller权限\n";
            system("pause");
            break;
        case '4':
            beforeRunAsSystem();
            std::cout << "[+]如果启动成功，在新窗口输入whoami /user\n返回nt authority\\system（或者输入whoami /groups | findstr Trusted无结果），说明成功获取了SYSTEM权限\n";
            system("pause");
            break;
        case '5':
            system("whoami");
            system("whoami /groups | findstr Trusted");
            std::cout << "[+] trustedinstaller和SYSTEM都会返回nt authority\\system\n";
            system("pause");
            break;
        case '6':
            if (IsTrustedInstaller()) {
                std::cout << "[*] 当前已经是trustedinstaller权限\n";
                std::cout << "无需重复提权，按任意键返回主菜单...\n";
                system("pause");
                break;
            }
            beforeRunAsSystem();
            std::cout << "[+] 完成！\n";
            system("pause");
            break;
        case '7':
            {
                if (!IsAdministratorDisabled()) {
                    std::cout << "[*] Administrator账户已开启，无需操作，按任意键返回主菜单...\n";
                    system("pause");
                    break;
                }
                std::cout << "请输入要设置的Administrator密码（建议复杂密码）: ";
                std::wstring password = ReadPasswordMasked();
                std::cout << "请再次输入密码以确认: ";
                std::wstring confirmPassword = ReadPasswordMasked();
                if (password != confirmPassword) {
                    std::cout << "[-] 两次输入的密码不匹配，操作取消，按任意键返回主菜单...\n";
                    system("pause");
                    break;
                }
                if (SetAdministratorPassword(password) && EnableAdministrator()) {
                    std::cout << "[+] 成功启用Administrator账户并设置密码，按任意键返回主菜单...\n";
                } 
                else {
                    std::cout << "[-] 启用Administrator账户失败，按任意键返回主菜单...\n";
                }
                system("pause");
                break;
            }
        case '8':
            {
                system("cls");
                std::cout << "请输入要赋予完全控制权限的文件夹路径(可带引号): ";
                std::wstring folderPath;
                std::wcin >> folderPath;
                if (GrantFullControlToCurrentUser(folderPath)) {
                    std::cout << "[+] 成功赋予当前用户对该文件夹的完全控制权限，按任意键返回主菜单...\n";
                } else {
                    std::cout << "[-] 赋予权限失败，可能是路径错误或权限不足，按任意键返回主菜单...\n";
                }
                system("pause");
                break;
            }
        case 'e':
            {
                int ret = MessageBoxW(nullptr, L"不要退出好不好，我想一直陪着主人喵", L"要退出了喵!", MB_ICONINFORMATION | MB_OKCANCEL);
                if (ret != IDOK) {
                    break;
                }
                std::cout << "[+] 已退出，代码:0\n";
                goto here;
            }
        case 'h':
            helpCenter();
            break;
        default:
            std::cout << "[-] 未知命令\n";
            system("pause");
            break;
    }
    goto h;
here:
    system("pause");
    return 0;
}
