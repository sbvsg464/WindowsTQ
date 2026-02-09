// menu.h
#pragma once

#include "lib.h"
#include "acl.h"
#include "SYSTEM.h"
#include "token.h"
#include "policy.h"
#include "else.h"

void ShowMainMenu() {
here:
    system("cls");
    std::cout << "欢迎!版本:5.1 release\n请选择你想要的提权操作:\n"
    "1.更改PowerShell执行策略\n2.获取以administrator接管文件/文件夹功能\n3.获取有trustedinstaller权限的cmd\n"
    "4.获取有SYSTEM权限的cmd\n5.检查当前程序权限\n6.将本程序提权为trustedinstaller\n7.强开Administrator账户(支持Windows 10/11 Home)\n"
    "8.让此账户获取指定文件夹的完全控制权限\n9.打印所有特权进程\ne.exit\nh.help\n";
    char option;
    std::cin >> option;
    switch (option) {
        case '1':
            changePowershellPolicy();
            goto here;
        case '2':
            WriteRegFile();
            goto here;
        case '3':
            privilegeEscalationForTI();
            std::cout << "[+]如果启动成功，在新窗口输入whoami /groups | findstr Trusted\n有 NT SERVICE\\TrustedInstaller 行，说明成功获取了trustedinstaller权限\n";
            system("pause");
            goto here;
        case '4':
            beforeRunAsSystem();
            std::cout << "[+]如果启动成功，在新窗口输入whoami /user\n返回nt authority\\system（或者输入whoami /groups | findstr Trusted无结果），说明成功获取了SYSTEM权限\n";
            system("pause");
            goto here;
        case '5':
            system("whoami");
            system("whoami /groups | findstr Trusted");
            std::cout << "[+] trustedinstaller和SYSTEM都会返回nt authority\\system\n";
            system("pause");
            goto here;
        case '6':
            {
                if (IsTrustedInstaller()) {
                std::cout << "[*] 当前已经是trustedinstaller权限\n";
                std::cout << "无需重复提权，按任意键返回主菜单...\n";
                system("pause");
                goto here;
                }
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
                system(psCmd.c_str());
                system("pause");
                goto here;
            }
        case '7':
            {
                if (!IsAdministratorDisabled()) {
                    std::cout << "[*] Administrator账户已开启，无需操作，按任意键返回主菜单...\n";
                    system("pause");
                    goto here;
                }
                std::cout << "请输入要设置的Administrator密码（建议复杂密码）: ";
                std::wstring password = ReadPasswordMasked();
                std::cout << "请再次输入密码以确认: ";
                std::wstring confirmPassword = ReadPasswordMasked();
                if (password != confirmPassword) {
                    std::cout << "[-] 两次输入的密码不匹配，操作取消，按任意键返回主菜单...\n";
                    system("pause");
                    goto here;
                }
                if (SetAdministratorPassword(password) && EnableAdministrator()) {
                    std::cout << "[+] 成功启用Administrator账户并设置密码，按任意键返回主菜单...\n";
                } 
                else {
                    std::cout << "[-] 启用Administrator账户失败，按任意键返回主菜单...\n";
                }
                system("pause");
                goto here;
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
                goto here;
            }
        case '9':
            EnumProcessTokens();
            system("pause");
            goto here;
        case 'e':
            {
                int ret = MessageBoxW(nullptr, L"不要退出好不好，我想一直陪着主人喵", L"要退出了喵!", MB_ICONINFORMATION | MB_OKCANCEL);
                if (ret == IDOK) {
                    break;
                }
                std::cout << "[+] 已退出，代码:0\n";
                goto here;
            }
        case 'h':
            helpCenter();
            goto here;
        default:
            std::cout << "[-] 未知命令\n";
            system("pause");
            goto here;
    }
    return;
}
