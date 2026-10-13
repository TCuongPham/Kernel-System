#include <windows.h>
#include <iostream>

// Định nghĩa kiểu hàm cho MessageBoxA
typedef int (WINAPI* pfnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
pfnMessageBoxA g_OriginalMessageBoxA = nullptr;

#if defined(_M_X64) || defined(__x86_64__)
// Trên x64: Dùng absolute 64-bit jump (14 bytes)
// mov rax, <64-bit address> (48 B8 + 8 bytes)
// jmp rax                   (FF E0)
#pragma pack(push, 1)
struct JumpPatch64 {
    BYTE movRax[2];   // 0x48, 0xB8
    void* targetAddr; // 8 bytes address
    BYTE jmpRax[2];   // 0xFF, 0xE0
};
#pragma pack(pop)
const size_t PATCH_SIZE = sizeof(JumpPatch64); // 14 bytes

#else
// Trên x86: Dùng relative 32-bit jump (5 bytes)
// jmp <32-bit offset>       (E9 + 4 bytes)
#pragma pack(push, 1)
struct JumpPatch32 {
    BYTE jmpOpcode;   // 0xE9
    DWORD relativeOffset;
};
#pragma pack(pop)
const size_t PATCH_SIZE = 5;
#endif

// Bộ đệm lưu bytes gốc để phục hồi hoặc tạo trampoline
BYTE g_OriginalBytes[PATCH_SIZE] = { 0 };
void* g_TargetFunction = nullptr;

// Hàm can thiệp (Hooked Function)
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "[Inline Hook] Da chan duoc loi goi MessageBoxA!\n";
    std::cout << "  - Text goc:    \"" << lpText << "\"\n";
    std::cout << "  - Caption goc: \"" << lpCaption << "\"\n";

    // Để có thể gọi lại hàm gốc mà không bị lặp đệ quy, ta tạm thời unhook (restore bytes gốc)
    DWORD oldProtect = 0;
    VirtualProtect(g_TargetFunction, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(g_TargetFunction, g_OriginalBytes, PATCH_SIZE);
    VirtualProtect(g_TargetFunction, PATCH_SIZE, oldProtect, &oldProtect);

    // Gọi hàm gốc
    int result = MessageBoxA(hWnd, 
                             "Noi dung nay da bi can thiep boi Inline Hook!", 
                             "[INLINE HOOKED] Thong bao", 
                             uType | MB_ICONINFORMATION);

    // Cài lại Hook sau khi gọi xong
    VirtualProtect(g_TargetFunction, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
#if defined(_M_X64) || defined(__x86_64__)
    JumpPatch64 patch;
    patch.movRax[0] = 0x48;
    patch.movRax[1] = 0xB8;
    patch.targetAddr = reinterpret_cast<void*>(HookedMessageBoxA);
    patch.jmpRax[0] = 0xFF;
    patch.jmpRax[1] = 0xE0;
    memcpy(g_TargetFunction, &patch, sizeof(patch));
#else
    JumpPatch32 patch;
    patch.jmpOpcode = 0xE9;
    patch.relativeOffset = reinterpret_cast<DWORD>(HookedMessageBoxA) - (reinterpret_cast<DWORD>(g_TargetFunction) + 5);
    memcpy(g_TargetFunction, &patch, sizeof(patch));
#endif
    VirtualProtect(g_TargetFunction, PATCH_SIZE, oldProtect, &oldProtect);

    return result;
}

// Cài đặt Inline Hook
bool InstallInlineHook(void* targetFunc, void* hookFunc)
{
    g_TargetFunction = targetFunc;

    // 1. Sao chép các bytes đầu tiên của hàm gốc để lưu trữ
    memcpy(g_OriginalBytes, targetFunc, PATCH_SIZE);

    // 2. Mở quyền Execute + Read + Write cho vùng mã máy của hàm mục tiêu
    DWORD oldProtect = 0;
    if (!VirtualProtect(targetFunc, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[-] VirtualProtect that bai: " << GetLastError() << "\n";
        return false;
    }

    // 3. Ghi đè mã lệnh nhảy sang hàm Hook
#if defined(_M_X64) || defined(__x86_64__)
    JumpPatch64 patch;
    patch.movRax[0] = 0x48;
    patch.movRax[1] = 0xB8;
    patch.targetAddr = hookFunc;
    patch.jmpRax[0] = 0xFF;
    patch.jmpRax[1] = 0xE0;
    memcpy(targetFunc, &patch, sizeof(patch));
#else
    JumpPatch32 patch;
    patch.jmpOpcode = 0xE9;
    patch.relativeOffset = reinterpret_cast<DWORD>(hookFunc) - (reinterpret_cast<DWORD>(targetFunc) + 5);
    memcpy(targetFunc, &patch, sizeof(patch));
#endif

    // 4. Khôi phục lại quyền bộ nhớ
    VirtualProtect(targetFunc, PATCH_SIZE, oldProtect, &oldProtect);

    // 5. Làm sạch CPU Instruction Cache để đảm bảo CPU nạp mã máy mới
    FlushInstructionCache(GetCurrentProcess(), targetFunc, PATCH_SIZE);

    std::cout << "[+] Da cai dat Inline Hook thanh cong (" << PATCH_SIZE << " bytes patched)!\n";
    return true;
}

int main()
{
    std::cout << "===INLINE HOOKING ===\n\n";

    // 1. Lần gọi thứ 1: Trước khi Hook
    std::cout << "[1] Goi MessageBoxA lan 1 (chua hook)...\n";
    MessageBoxA(NULL, "Day la MessageBoxA ban dau.", "Thong bao binh thuong", MB_OK);

    // 2. Lấy con trỏ tới hàm MessageBoxA trong user32.dll
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    void* pfnTarget = reinterpret_cast<void*>(GetProcAddress(hUser32, "MessageBoxA"));
    if (!pfnTarget) {
        std::cerr << "[-] Khong tim thay ham MessageBoxA!\n";
        return 1;
    }

    // 3. Cài đặt Inline Hook
    std::cout << "\n[2] Dang cai dat Inline Hook...\n";
    if (!InstallInlineHook(pfnTarget, reinterpret_cast<void*>(HookedMessageBoxA))) {
        std::cerr << "[-] Cai Inline Hook that bai!\n";
        return 1;
    }

    // 4. Lần gọi thứ 2: Sau khi Hook (lệnh gọi trực tiếp hoặc qua con trỏ đều bị hook)
    std::cout << "\n[3] Goi MessageBoxA lan 2 (da hook)...\n";
    MessageBoxA(NULL, "Tin nhan thu hai sau khi da hook.", "Hop thoai 2", MB_OK);

    std::cout << "\n=== HOAN THANH DEMO INLINE HOOK ===\n";
    std::cout << "Nhan Enter de thoat...";
    std::cin.get();
    return 0;
}
