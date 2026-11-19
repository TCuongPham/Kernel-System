#include <windows.h>
#include <cstdint>
#include <cstring>
#include <iostream>

#pragma comment(lib, "User32.lib")

// Định nghĩa kiểu hàm MessageBoxA
typedef int (WINAPI* pfnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// Con trỏ tới vùng Trampoline
pfnMessageBoxA g_OriginalMessageBoxA = nullptr;

#if defined(_M_X64) || defined(__x86_64__)
// Trên x64: Dùng absolute 64-bit jump (12 bytes)
// mov rax, <64-bit address> (48 B8 + 8 bytes)
// jmp rax                   (FF E0)
#pragma pack(push, 1)
struct JumpPatch64 {
	BYTE movRax[2];   // 0x48, 0xB8 (mov rax, <64-bit address>)
    void* targetAddr; // 8 bytes address
	BYTE jmpRax[2];   // 0xFF, 0xE0 (jmp rax)
};
#pragma pack(pop)
constexpr size_t PATCH_SIZE = sizeof(JumpPatch64); // 12 bytes

#else
// Trên x86: Dùng relative 32-bit jump (5 bytes)
// jmp <32-bit offset>       (E9 + 4 bytes)
#pragma pack(push, 1)
struct JumpPatch32 {
	BYTE jmpOpcode;   // 0xE9 (JMP rel32)
    DWORD relativeOffset;
};
#pragma pack(pop)
constexpr size_t PATCH_SIZE = sizeof(JumpPatch32); // 5 bytes
#endif

// Trạng thái để phục hồi khi gỡ hook
BYTE* g_Trampoline = nullptr; // Con trỏ tới vùng Trampoline
BYTE g_OriginalBytes[32] = { 0 };   // Lưu trữ các bytes của hàm gốc
size_t g_StolenBytesLen = 0;    // Số bytes đã bị tráo đổi
void* g_TargetFunction = nullptr; // Con trỏ tới hàm gốc (MessageBoxA)

// Ghi lệnh nhảy từ src -> dst
void WriteJump(void* src, void* dst)
{
#if defined(_M_X64) || defined(__x86_64__)
    JumpPatch64 patch{};
    patch.movRax[0] = 0x48;
    patch.movRax[1] = 0xB8;
    patch.targetAddr = dst;
    patch.jmpRax[0] = 0xFF;
    patch.jmpRax[1] = 0xE0;
	// Ghi đè bytes
    std::memcpy(src, &patch, sizeof(patch));
#else
    JumpPatch32 patch{};
    patch.jmpOpcode = 0xE9;
    patch.relativeOffset = static_cast<DWORD>(
        reinterpret_cast<uintptr_t>(dst) - (reinterpret_cast<uintptr_t>(src) + 5)
    );
    std::memcpy(src, &patch, sizeof(patch));
#endif
}

// Cấp phát vùng nhớ thực thi (RWX) nằm gần targetFunc 
BYTE* AllocNear(void* targetFunc, size_t size)
{
	// Lấy thông tin hệ thống để biết kích thước trang bộ nhớ
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    const uintptr_t step = si.dwAllocationGranularity; // thường là 64KB (đơn vị cấp phát virtual mem)

	// Tính và làm tròn địa chỉ cơ sở (base) của trang chứa targetFunc
    const uintptr_t base = reinterpret_cast<uintptr_t>(targetFunc) & ~(step - 1);

    const uintptr_t maxRange = 0x40000000; // 1GB

    for (uintptr_t offset = step; offset < maxRange; offset += step) {
		// Cấp phát vùng nhớ phía trên targetFunc
        if (void* p = VirtualAlloc(reinterpret_cast<void*>(base + offset), size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
            return reinterpret_cast<BYTE*>(p);
        }
        if (base > offset) {
            if (void* p = VirtualAlloc(reinterpret_cast<void*>(base - offset), size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
                return reinterpret_cast<BYTE*>(p);
            }
        }
    }
    return nullptr;
}

// Trampoline 
void* CreateTrampoline(void* targetFunc, size_t stolenBytesLen)
{
    if (stolenBytesLen < PATCH_SIZE || stolenBytesLen > sizeof(g_OriginalBytes)) {
        return nullptr;
    }

    // 1. Cấp phát vùng nhớ RWX gần hàm gốc để chứa [stolenBytes] + [Jump quay về]
    BYTE* trampoline = AllocNear(targetFunc, stolenBytesLen + PATCH_SIZE);
    if (!trampoline) {
        std::cerr << "[-] AllocNear that bai!\n";
        return nullptr;
    }

    // 2. Chép các lệnh đầu tiên của hàm gốc sang Trampoline
    std::memcpy(trampoline, targetFunc, stolenBytesLen);

#if defined(_M_X64) || defined(__x86_64__)
    // 3. Xử lý lệnh ở dòng thứ 3 của MessageBoxA (Windows 10/11 x64):
    //    44 39 1D [disp32]   
    //    Nếu có lệnh này ở vị trí +7 (dài 7 bytes -> kết thúc ở +14), phải tính lại disp32 theo vị trí Trampoline mới
    if (stolenBytesLen >= 14 &&
        trampoline[7] == 0x44 && trampoline[8] == 0x39 && trampoline[9] == 0x1D) {

		// Lấy giá trị disp32 (offset) gốc từ lệnh cmp [rip+disp32],r11d
        INT32 origDisp = 0;
        std::memcpy(&origDisp, reinterpret_cast<BYTE*>(targetFunc) + 10, sizeof(origDisp));

		// Tính địa chỉ tuyệt đối lệnh cmp [rip+disp32],r11d đang trỏ
        BYTE* ripAfterOrig = reinterpret_cast<BYTE*>(targetFunc) + 14;
        BYTE* targetGlobal = ripAfterOrig + origDisp;

		// Tính lại disp32 mới từ Trampoline sang targetGlobal
        BYTE* ripAfterTrampoline = trampoline + 14;
        ptrdiff_t newDiff = targetGlobal - ripAfterTrampoline;

        if (newDiff < INT32_MIN || newDiff > INT32_MAX) {
            std::cerr << "[-] Khoang cach RIP-relative vuot qua +-2GB!\n";
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return nullptr;
        }

		// Ghi lại disp32 mới vào lệnh cmp [rip+disp32],r11d trong Trampoline
        INT32 newDisp = static_cast<INT32>(newDiff);
        std::memcpy(trampoline + 10, &newDisp, sizeof(newDisp));
    }
#endif

    // 4. Nối lệnh nhảy ở cuối Trampoline quay về phần thân còn lại của hàm gốc (targetFunc + stolenBytesLen)
    BYTE* returnAddr = reinterpret_cast<BYTE*>(targetFunc) + stolenBytesLen;
    WriteJump(trampoline + stolenBytesLen, returnAddr);

    // 5. Đồng bộ Instruction Cache cho vùng nhớ Trampoline mới tạo
    FlushInstructionCache(GetCurrentProcess(), trampoline, stolenBytesLen + PATCH_SIZE);

    return trampoline;
}

// Hàm Hook
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "[Inline Hook - Trampoline] Chan MessageBoxA!\n";
    std::cout << "  - Text goc:    \"" << (lpText ? lpText : "(null)") << "\"\n";
    std::cout << "  - Caption goc: \"" << (lpCaption ? lpCaption : "(null)") << "\"\n";

    // Gọi qua Trampoline -> chạy 14 bytes đầu -> nhảy về thân hàm MessageBoxA gốc
    return g_OriginalMessageBoxA(
        hWnd,
        "Noi dung da bi can thiep qua Trampoline!",
        "[TRAMPOLINE HOOKED] Thong bao",
        uType | MB_ICONINFORMATION
    );
}

// Cài đặt Inline Hook sử dụng Trampoline
bool InstallInlineHook(void* targetFunc, void* hookFunc, size_t stolenBytesLen)
{
    g_TargetFunction = targetFunc;
    g_StolenBytesLen = stolenBytesLen;

    // Lưu lại bytes gốc để có thể gỡ hook hoàn toàn khi thoát
    std::memcpy(g_OriginalBytes, targetFunc, stolenBytesLen);

    // 1. Tạo Trampoline trước khi sửa hàm gốc
    g_Trampoline = reinterpret_cast<BYTE*>(CreateTrampoline(targetFunc, stolenBytesLen));
    if (!g_Trampoline) {
        return false;
    }
	// Chuyển kiểu con trỏ Trampoline sang kiểu hàm gốc để gọi lại
    g_OriginalMessageBoxA = reinterpret_cast<pfnMessageBoxA>(g_Trampoline);

    // 2. Mở quyền ghi và ghi lệnh nhảy ở đầu hàm gốc sang HookedMessageBoxA
    DWORD oldProtect = 0;
    if (!VirtualProtect(targetFunc, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[-] VirtualProtect that bai: " << GetLastError() << "\n";
        VirtualFree(g_Trampoline, 0, MEM_RELEASE);
        g_Trampoline = nullptr;
        return false;
    }

    WriteJump(targetFunc, hookFunc);

    VirtualProtect(targetFunc, PATCH_SIZE, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), targetFunc, PATCH_SIZE);

    std::cout << "Cai dat Inline Hook (Trampoline)\n";
    std::cout << "    - Target Func: " << targetFunc << "\n";
    std::cout << "    - Trampoline:  " << static_cast<void*>(g_Trampoline) << "\n";
    std::cout << "    - Stolen Bytes: " << stolenBytesLen << " bytes\n";
    return true;
}

// Gỡ bỏ Hook và giải phóng Trampoline
void UninstallInlineHook()
{
    if (!g_TargetFunction || g_StolenBytesLen == 0) return;

    DWORD oldProtect = 0;
    if (VirtualProtect(g_TargetFunction, g_StolenBytesLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::memcpy(g_TargetFunction, g_OriginalBytes, g_StolenBytesLen);
        VirtualProtect(g_TargetFunction, g_StolenBytesLen, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), g_TargetFunction, g_StolenBytesLen);
    }

    if (g_Trampoline) {
        VirtualFree(g_Trampoline, 0, MEM_RELEASE);
        g_Trampoline = nullptr;
    }
    g_OriginalMessageBoxA = nullptr;
}

int main()
{
    // 1. Lần gọi thứ 1: Trước Hook
    std::cout << "[1] Goi MessageBoxA lan 1 (chua hook)...\n";
    MessageBoxA(NULL, "MessageBoxA ban dau.", "Thong bao binh thuong", MB_OK);

    // 2. Lấy địa chỉ hàm MessageBoxA trong user32.dll
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        std::cerr << "[-] Khong load duoc user32.dll!\n";
        return 1;
    }

    void* pfnTarget = reinterpret_cast<void*>(GetProcAddress(hUser32, "MessageBoxA"));
    if (!pfnTarget) {
        std::cerr << "[-] Khong tim thay ham MessageBoxA!\n";
        return 1;
    }

    // 3. Số byte ở đầu MessageBoxA cần lấy (>= PATCH_SIZE):
    //    - x64 (Win10/11): sub rsp,38h (4) + xor r11d,r11d (3) + cmp [rip+...],r11d (7) = 14 bytes
    //    - x86:            mov edi,edi (2) + push ebp (1) + mov ebp,esp (2) = 5 bytes
#if defined(_M_X64) || defined(__x86_64__)
    constexpr size_t stolenBytesLen = 14;
#else
    constexpr size_t stolenBytesLen = 5;
#endif

    // 4. Cài đặt Inline Hook 
    if (!InstallInlineHook(pfnTarget, reinterpret_cast<void*>(HookedMessageBoxA), stolenBytesLen)) {
        std::cerr << "[-] Cai Inline Hook that bai!\n";
        return 1;
    }

    // 5. Lần gọi thứ 2: Sau khi Hook
    std::cout << "\n[3] Goi MessageBoxA lan 2 (da hook bang Trampoline)...\n";
    MessageBoxA(NULL, "Tin nhan thu hai sau khi da hook.", "Hop thoai 2", MB_OK);

    // 6. Gỡ hook và giải phóng bộ nhớ Trampoline
    UninstallInlineHook();
    std::cout << "\n[4] Da go Hook. Goi MessageBoxA lan 3 (tro lai binh thuong)...\n";
    MessageBoxA(NULL, "Hook da duoc go bo.", "Hop thoai 3", MB_OK);

    return 0;
}
