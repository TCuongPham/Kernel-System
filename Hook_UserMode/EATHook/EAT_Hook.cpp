#include <windows.h>
#include <cstdint>
#include <cstring>
#include <iostream>

// Định nghĩa con trỏ hàm có cùng prototype với MessageBoxA
typedef int (WINAPI* pfnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
pfnMessageBoxA g_OriginalMessageBoxA = nullptr;

#if defined(_M_X64) || defined(__x86_64__)
// Trên x64, RVA trong EAT chỉ có 32-bit (DWORD) nên chỉ trỏ tới được vùng [imageBase, imageBase + 4GB).
// Nếu hàm Hook nằm ngoài phạm vi, cấp phát một Relay Stub nằm trong +4GB để nhảy tuyệt đối 64-bit.
#pragma pack(push, 1)
struct JumpPatch64 {
    BYTE movRax[2];   // 0x48, 0xB8 (mov rax, <64-bit address>)
    void* targetAddr; // 8 bytes address
    BYTE jmpRax[2];   // 0xFF, 0xE0 (jmp rax)
};
#pragma pack(pop)

void* AllocateRelayStubInRange(uintptr_t moduleBase, void* hookFunc)
{
    // Lấy thông tin hệ thống để biết kích thước trang bộ nhớ
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    const uintptr_t gran = si.dwAllocationGranularity; // thường là 64KB (đơn vị cấp phát virtual mem)

    // Lấy giới hạn trên
    const uintptr_t maxEnd = (moduleBase <= UINTPTR_MAX - 0xFFFFFFFFULL)
        ? (moduleBase + 0xFFFFFFFFULL) // (+4GB)
        : UINTPTR_MAX;

    // Làm tròn địa chỉ bắt đầu duyệt lên bội số gần nhất của 64KB
    uintptr_t addr = (moduleBase + gran - 1) & ~(gran - 1);

    while (addr < maxEnd) {
        // Cấu trúc khối các trang virtual mem
        MEMORY_BASIC_INFORMATION mbi{};

        // Duyệt qua từng trang bộ nhớ ảo có cùng state nối tiếp từ addr
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
            break;
        }

        uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress); // Địa chỉ bắt đầu của khối trang nhớ
        uintptr_t regionEnd = regionBase + mbi.RegionSize; //Kích thước của khối trang nhớ

        if (mbi.State == MEM_FREE) {
            uintptr_t allocAddr = (addr + gran - 1) & ~(gran - 1); // Làm tròn địa chỉ cấp phát lên bội số gần nhất của 64KB

            if (allocAddr >= moduleBase &&
                allocAddr + sizeof(JumpPatch64) <= regionEnd &&
                (allocAddr - moduleBase) + sizeof(JumpPatch64) <= 0xFFFFFFFFULL) {
                // Cấp phát 1 trang nhớ
                void* stub = VirtualAlloc(reinterpret_cast<LPVOID>(allocAddr),
                                          si.dwPageSize,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
                if (stub) {
                    JumpPatch64 patch{};
                    patch.movRax[0] = 0x48;
                    patch.movRax[1] = 0xB8;
                    patch.targetAddr = hookFunc;
                    patch.jmpRax[0] = 0xFF;
                    patch.jmpRax[1] = 0xE0;

                    std::memcpy(stub, &patch, sizeof(patch));
                    FlushInstructionCache(GetCurrentProcess(), stub, sizeof(patch));
                    return stub;
                }
            }
        }

        if (regionEnd <= addr) {
            break;
        }
        // Nhảy đến khối các trang tiếp theo
        addr = regionEnd;
    }

    return nullptr;
}
#endif

// Hàm Hook
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "[EAT Hook] Da chan MessageBoxA!\n";
    std::cout << "  - Noi dung goc: \"" << lpText << "\"\n";
    std::cout << "  - Tieu de goc:  \"" << lpCaption << "\"\n";

    // Thay đổi nội dung chuyển tiếp cho hàm gốc (hoặc chặn gọi hàm khác)
    LPCSTR customText = "Noi dung nay da bi can thiep boi EAT Hook!";
    LPCSTR customCaption = "[HOOKED] Thong bao";

    // Gọi lại hàm gốc
    return g_OriginalMessageBoxA(hWnd, customText, customCaption, uType | MB_ICONWARNING);
}

// Hàm duyệt PE Header và hook EAT
bool InstallEATHook(const char* targetDllName, const char* targetFuncName, void* hookFunc, void** ppOriginalFunc)
{
    // 1. Lấy Base Address của DLL 
    uintptr_t imageBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(targetDllName));
    if (!imageBase) {
        std::cerr << "[-] Khong tim thay module " << targetDllName << " trong tien trinh!\n";
        return false;
    }

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

    // 4. Lấy Data Directory của phần Export (IMAGE_DIRECTORY_ENTRY_EXPORT)
    IMAGE_DATA_DIRECTORY exportDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0) {
        std::cerr << "[-] Khong tim thay bang Export!\n";
        return false;
    }

    // 5. Trỏ tới IMAGE_EXPORT_DIRECTORY và 3 bảng của EAT
    auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(imageBase + exportDirectory.VirtualAddress);

    auto addressOfFunctions = reinterpret_cast<DWORD*>(imageBase + exportDir->AddressOfFunctions);
    auto addressOfNames = reinterpret_cast<DWORD*>(imageBase + exportDir->AddressOfNames);
    auto addressOfNameOrdinals = reinterpret_cast<WORD*>(imageBase + exportDir->AddressOfNameOrdinals);

    // 6. Duyệt qua các hàm được export theo tên
    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* currentFuncName = reinterpret_cast<const char*>(imageBase + addressOfNames[i]);

        if (std::strcmp(currentFuncName, targetFuncName) == 0) {
            WORD ordinalIndex = addressOfNameOrdinals[i];
            if (ordinalIndex >= exportDir->NumberOfFunctions) {
                std::cerr << "[-] Ordinal khong hop le!\n";
                return false;
            }

            DWORD originalRVA = addressOfFunctions[ordinalIndex];

            // Kiểm tra Forwarded Export
            if (originalRVA >= exportDirectory.VirtualAddress &&
                originalRVA < exportDirectory.VirtualAddress + exportDirectory.Size) {
                std::cerr << "[-] Ham " << targetFuncName << " la forwarded export, khong ho tro hook truc tiep!\n";
                return false;
            }

            // Lưu lại con trỏ hàm gốc
            if (ppOriginalFunc) {
                *ppOriginalFunc = reinterpret_cast<void*>(imageBase + originalRVA);
            }

            // Tính RVA mới (32-bit) tương đối so với imageBase của DLL mục tiêu
            DWORD newRVA = 0;
            uintptr_t hookAddr = reinterpret_cast<uintptr_t>(hookFunc);

#if defined(_M_X64) || defined(__x86_64__)
            // Nếu địa chỉ hàm hook trong phạm vi 4GB
            if (hookAddr >= imageBase && (hookAddr - imageBase) <= 0xFFFFFFFFULL) {
                newRVA = static_cast<DWORD>(hookAddr - imageBase);
            } 
            else {
                void* relayStub = AllocateRelayStubInRange(imageBase, hookFunc);
                if (!relayStub) {
                    std::cerr << "[-] Khong cap phat duoc relay stub trong pham vi 4GB cua " << targetDllName << "!\n";
                    return false;
                }
                newRVA = static_cast<DWORD>(reinterpret_cast<uintptr_t>(relayStub) - imageBase);
            }
#else
            newRVA = static_cast<DWORD>(hookAddr - imageBase);
#endif

            // Mở quyền ghi (Write) cho trang nhớ chứa ô EAT
            DWORD oldProtect = 0;
            if (!VirtualProtect(&addressOfFunctions[ordinalIndex], sizeof(DWORD), PAGE_READWRITE, &oldProtect)) {
                std::cerr << "[-] VirtualProtect that bai: " << GetLastError() << "\n";
                return false;
            }

            // Ghi đè RVA trong EAT trỏ sang hàm Hook (hoặc Relay Stub)
            addressOfFunctions[ordinalIndex] = newRVA;

            // Khôi phục lại quyền
            VirtualProtect(&addressOfFunctions[ordinalIndex], sizeof(DWORD), oldProtect, &oldProtect);

            std::cout << "[+] Hook EAT cho ham: " << targetFuncName << " (trong " << targetDllName << ")\n";
            return true;
        }
    }

    std::cerr << "[-] Khong tim thay ham " << targetFuncName << " trong EAT cua " << targetDllName << "\n";
    return false;
}

int main()
{
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        std::cerr << "[-] Khong the nap user32.dll!\n";
        return 1;
    }

    // 1. Lần 1: Trước khi Hook (gọi qua GetProcAddress)
    std::cout << "[1] Goi MessageBoxA qua GetProcAddress truoc khi Hook...\n";
    auto pMsgBoxBefore = reinterpret_cast<pfnMessageBoxA>(GetProcAddress(hUser32, "MessageBoxA"));
    if (pMsgBoxBefore) {
        pMsgBoxBefore(NULL, "Day la hop thoai ban dau chua bi hook.", "Original Dialog", MB_OK);
    }

    // 2. Cài đặt EAT Hook
    if (!InstallEATHook("user32.dll", "MessageBoxA",
                        reinterpret_cast<void*>(HookedMessageBoxA),
                        reinterpret_cast<void**>(&g_OriginalMessageBoxA))) {
        std::cerr << "[-] Cai dat Hook that bai!\n";
        return 1;
    }

    // 3. Lần 2: Sau khi Hook (GetProcAddress sẽ đọc EAT và trả về hàm Hook)
    std::cout << "\n[3] Goi MessageBoxA qua GetProcAddress sau khi Hook...\n";
    auto pMsgBoxAfter = reinterpret_cast<pfnMessageBoxA>(GetProcAddress(hUser32, "MessageBoxA"));
    if (pMsgBoxAfter) {
        pMsgBoxAfter(NULL, "Day la tin nhan goi lan 2.", "Original Dialog 2", MB_OK);
    }

    std::cin.get();
    return 0;
}
