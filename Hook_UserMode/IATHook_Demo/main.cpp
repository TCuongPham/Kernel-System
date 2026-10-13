#include <windows.h>
#include <iostream>

// Định nghĩa con trỏ hàm có cùng prototype với MessageBoxA
typedef int (WINAPI* pfnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
pfnMessageBoxA g_OriginalMessageBoxA = nullptr;

// Hàm giả lập (Hooked Function) sẽ được gọi thay thế cho MessageBoxA gốc
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "[IAT Hook] Da chan duoc goi MessageBoxA!\n";
    std::cout << "  - Noi dung goc: \"" << lpText << "\"\n";
    std::cout << "  - Tieu de goc:  \"" << lpCaption << "\"\n";

    // Thay đổi nội dung hiển thị trước khi chuyển tiếp cho hàm gốc (hoặc có thể chặn hoàn toàn)
    LPCSTR customText = "Noi dung nay da bi can thiep boi IAT Hook!";
    LPCSTR customCaption = "[HOOKED] Thong bao";

    // Gọi lại hàm gốc để hiển thị MessageBox đã bị sửa nội dung
    return g_OriginalMessageBoxA(hWnd, customText, customCaption, uType | MB_ICONWARNING);
}

// Hàm thực hiện duyệt PE Header và tráo con trỏ trong IAT
bool InstallIATHook(const char* targetDllName, const char* targetFuncName, void* hookFunc, void** ppOriginalFunc)
{
    // 1. Lấy Base Address của module hiện tại (chính là ImageBase của file .exe trong bộ nhớ)
    uintptr_t imageBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    if (!imageBase) return false;

    // 2. Trỏ tới DOS Header
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] DOS Header khong hop le!\n";
        return false;
    }

    // 3. Trỏ tới NT Headers
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] NT Headers khong hop le!\n";
        return false;
    }

    // 4. Lấy Data Directory của phần Import (IMAGE_DIRECTORY_ENTRY_IMPORT)
    IMAGE_DATA_DIRECTORY importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0) {
        std::cerr << "[-] Khong tim thay bang Import!\n";
        return false;
    }

    // 5. Duyệt qua danh sách các DLL được import (IMAGE_IMPORT_DESCRIPTOR)
    auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(imageBase + importDirectory.VirtualAddress);

    for (; importDescriptor->Name != 0; ++importDescriptor) {
        const char* currentDllName = reinterpret_cast<const char*>(imageBase + importDescriptor->Name);
        
        // So sánh tên DLL (không phân biệt hoa thường)
        if (_stricmp(currentDllName, targetDllName) == 0) {
            // FirstThunk trỏ tới IAT (Import Address Table) - bảng chứa con trỏ hàm thực tế
            auto thunkIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + importDescriptor->FirstThunk);

            // OriginalFirstThunk trỏ tới INT (Import Name Table) - bảng chứa tên hàm
            // Một số compiler có thể để OriginalFirstThunk == 0, khi đó FirstThunk trỏ trực tiếp
            PIMAGE_THUNK_DATA thunkINT = nullptr;
            if (importDescriptor->OriginalFirstThunk != 0) {
                thunkINT = reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + importDescriptor->OriginalFirstThunk);
            } else {
                thunkINT = thunkIAT;
            }

            // Duyệt từng hàm được import từ DLL này
            for (; thunkIAT->u1.Function != 0; ++thunkIAT, ++thunkINT) {
                // Kiểm tra xem import theo Tên hay theo Ordinal (chỉ xét import theo Tên)
                if (!IMAGE_SNAP_BY_ORDINAL(thunkINT->u1.Ordinal)) {
                    auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBase + thunkINT->u1.AddressOfData);
                    
                    if (strcmp(importByName->Name, targetFuncName) == 0) {
                        // Lưu lại con trỏ hàm gốc
                        if (ppOriginalFunc) {
                            *ppOriginalFunc = reinterpret_cast<void*>(thunkIAT->u1.Function);
                        }

                        // Mở quyền ghi (Write) cho trang nhớ chứa ô IAT vì IAT mặc định thường chỉ có quyền Read
                        DWORD oldProtect = 0;
                        if (!VirtualProtect(&thunkIAT->u1.Function, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect)) {
                            std::cerr << "[-] VirtualProtect that bai: " << GetLastError() << "\n";
                            return false;
                        }

                        // Ghi đè con trỏ hàm sang hàm Hook của chúng ta
                        thunkIAT->u1.Function = reinterpret_cast<uintptr_t>(hookFunc);

                        // Khôi phục lại quyền ban đầu
                        VirtualProtect(&thunkIAT->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);

                        std::cout << "[+] Hook IAT thanh cong cho ham: " << targetFuncName << "\n";
                        return true;
                    }
                }
            }
        }
    }

    std::cerr << "[-] Khong tim thay ham " << targetFuncName << " trong DLL " << targetDllName << "\n";
    return false;
}

int main()
{
    std::cout << "===IAT HOOKING ===\n\n";

    // 1. Lần gọi thứ 1: Trước khi Hook
    std::cout << "[1] Goi MessageBoxA truoc khi Hook...\n";
    MessageBoxA(NULL, "Xin chao! Day la hop thoai ban dau chua bi hook.", "Original Dialog", MB_OK);

    // 2. Cài đặt IAT Hook
    std::cout << "\n[2] Dang cai dat IAT Hook...\n";
    if (!InstallIATHook("user32.dll", "MessageBoxA", 
                        reinterpret_cast<void*>(HookedMessageBoxA), 
                        reinterpret_cast<void**>(&g_OriginalMessageBoxA))) {
        std::cerr << "[-] Cai dat Hook that bai!\n";
        return 1;
    }

    // 3. Lần gọi thứ 2: Sau khi Hook (lời gọi sẽ bị chuyển hướng sang HookedMessageBoxA)
    std::cout << "\n[3] Goi MessageBoxA sau khi Hook...\n";
    MessageBoxA(NULL, "Day la tin nhan goi lan 2.", "Original Dialog 2", MB_OK);

    std::cout << "\n=== HOAN THANH DEMO IAT HOOK ===\n";
    std::cout << "Nhan Enter de thoat...";
    std::cin.get();
    return 0;
}
