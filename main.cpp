#include "menu.h"

int main() {
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
    ShowMainMenu();
    return 0;
}
