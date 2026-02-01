#include <iostream>
#include <fstream>
#include <filesystem>
#include <stdlib.h>
#include <windows.h>

/*
期待实现的功能：通过SYSTEM权限运行cmd.exe，从而实现最高权限的命令行窗口
*/

bool IsRunAsAdmin() {
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


void changePowershellPolicy() {
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
    std::cout << "操作完成，按任意键返回主菜单...\n";
    system("pause");
}

void WriteRegFile() {
    system("cls");
    std::ofstream reg("ti.reg", std::ios::binary);
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
    std::cout << "操作完成，按任意键返回主菜单...\n现在，右键一个文件，你将会看见一个“管理员接管（Take Ownership）”的选项，点击它即可将该文件的所有权和完全控制权限赋予administrator组\n";
    system("pause");
}

int main() {
    system("chcp 65001 > nul");
    if (!IsRunAsAdmin()) {
        MessageBoxA(nullptr, "请以管理员身份运行本程序", "权限不足", MB_ICONERROR | MB_OK);
        return 1;
    }
h:
    system("cls");
    std::cout << "欢迎!版本:V1.0 release\n请选择你想要的提权操作:\n1.更改PowerShell执行策略\n2.获取以administrator接管文件/文件夹功能\ne.exit\n";
    char option;
    std::cin >> option;
    switch (option) {
        case '1':
            changePowershellPolicy();
            break;
        case '2':
            WriteRegFile();
            break;
        case 'e':
            std::cout << "已退出，代码:0\n";
            goto here;
        default:
            std::cout << "未知命令\n";
            break;
    }
    goto h;
here:
    system("pause");
    return 0;
}
