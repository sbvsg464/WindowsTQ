// token.h
#pragma once

#include "lib.h"

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

bool IsAdministratorDisabled() {
    LPUSER_INFO_4 info = nullptr;
    if (NetUserGetInfo(nullptr, L"Administrator", 4, (LPBYTE*)&info) != NERR_Success)
        return true;
    bool disabled = info->usri4_flags & UF_ACCOUNTDISABLE;
    NetApiBufferFree(info);
    return disabled;
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


bool EnableAdministrator() {
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
};

PSID GetCurrentUserSid() {
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
