#include <windows.h>
#include <tlhelp32.h>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

// Prototype của CreateFileW
typedef HANDLE(WINAPI* pfnCreateFileW)(
	LPCWSTR lpFileName, // Tên file
	DWORD dwDesiredAccess, // Quyền truy cập (Read/Write)
	DWORD dwShareMode, // Chia sẻ (Share)
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, // Bảo mật
	DWORD dwCreationDisposition, // Tạo mới hay mở file
	DWORD dwFlagsAndAttributes,  // Thuộc tính file
	HANDLE hTemplateFile    // Template file
);

// Lưu lại thông tin mỗi ô IAT đã sửa để khôi phục khi gỡ DLL
struct HookedSlot {
    uintptr_t* iatEntry;
    uintptr_t originalAddr;
};

pfnCreateFileW g_OriginalCreateFileW = nullptr; // Con trỏ tới hàm CreateFileW gốc (trước khi hook)
std::vector<HookedSlot> g_HookedSlots; // Danh sách các ô IAT đã bị tráo đổi
CRITICAL_SECTION g_Lock{}; // Khóa bảo vệ danh sách g_HookedSlots và ghi log ra file
bool g_LockInitialized = false; 
wchar_t g_LogFilePath[MAX_PATH] = { 0 }; // Đường dẫn file log trong thư mục %TEMP% của tiến trình

// Kiểm tra chuỗi hay chứa chuỗi con (không phân biệt hoa thường)
bool ContainsCaseInsensitive(const wchar_t* haystack, const wchar_t* needle)
{
    if (!haystack || !needle || !*needle) return false;

	const size_t needleLen = std::wcslen(needle); // Chiều dài của chuỗi con

	// Vòng lặp từng vị trí của chuỗi haystack, so với needle
    for (const wchar_t* p = haystack; *p; ++p) {
        size_t i = 0;
        while (i < needleLen && p[i] &&
               std::towlower(p[i]) == std::towlower(needle[i])) {
            ++i;
        }
		// Nếu độ dài lặp khớp là tìm thấy
        if (i == needleLen) {
            return true;
        }
    }
    return false;
}

// Ghi log ra OutputDebugStringW và file log (dùng g_OriginalCreateFileW tránh đệ quy)
void WriteHookLog(const std::wstring& message)
{
	// Ghi ra OutputDebugStringW để theo dõi trong DebugView/Visual Studio
    OutputDebugStringW(message.c_str());

	// Nếu chưa có hàm gốc CreateFileW hoặc chưa xác định được đường dẫn file log thì không ghi ra file
    if (!g_OriginalCreateFileW || g_LogFilePath[0] == L'\0') {
        return;
    }

	// Ghi log ra file log 
	EnterCriticalSection(&g_Lock); // Khóa bảo vệ ghi log tránh đụng độ khi nhiều thread cùng ghi
    HANDLE hFile = g_OriginalCreateFileW(
        g_LogFilePath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
		OPEN_ALWAYS, // file chưa có tạo mới, có mở để ghi thêm
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        // Chuyển UTF-16 -> UTF-8 
		// Tính độ dài UTF-8 cần cấp phát
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, message.c_str(),
                                          static_cast<int>(message.size()),
                                          nullptr, 0, nullptr, nullptr);
        if (utf8Len > 0) {
			// Cấp phát buffer UTF-8 và chuyển đổi
            std::string utf8(utf8Len, '\0');
            WideCharToMultiByte(CP_UTF8, 0, message.c_str(),
                                static_cast<int>(message.size()),
                                utf8.data(), utf8Len, nullptr, nullptr);
			// Ghi ra file log
            DWORD written = 0;
            WriteFile(hFile, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        }
		CloseHandle(hFile); // Đóng handle file log
    }
	LeaveCriticalSection(&g_Lock); // Mở khóa sau khi ghi log xong
}

// Hàm Hook thay thế cho CreateFileW
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName, 
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    if (lpFileName) {
		// Sử dụng thread_local để tránh đệ quy vô hạn nếu g_OriginalCreateFileW bị gọi trong hook
		static thread_local bool t_InHook = false;
		// Nếu đang trong hook thì gọi hàm gốc để tránh đệ quy
        if (t_InHook) {
            return g_OriginalCreateFileW(
                lpFileName, dwDesiredAccess, dwShareMode,
                lpSecurityAttributes, dwCreationDisposition,
                dwFlagsAndAttributes, hTemplateFile
            );
        }
		// Đánh dấu đang trong hook để tránh đệ quy
        t_InHook = true;

        std::wstring logLine = L"[IAT Hook][CreateFileW] ";
        logLine += lpFileName;

        // Chặn tạo/truy cập nếu tên file chứa "block_test.txt"
        if (ContainsCaseInsensitive(lpFileName, L"block_test.txt")) {
            logLine += L" -> [BLOCKED]\r\n";
            WriteHookLog(logLine);
            t_InHook = false;
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }

        logLine += L"\r\n";
        WriteHookLog(logLine);
        t_InHook = false;
    }

	// Gọi hàm gốc CreateFileW để thực hiện mở file bình thường
    return g_OriginalCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}

// Kiểm tra tên DLL import có thuộc nhóm cung cấp CreateFileW không
bool IsTargetFileApiDll(const char* dllName)
{
    if (!dllName) return false;
	// Chỉ xét các DLL cung cấp CreateFileW: kernel32.dll, kernelbase.dll, api-ms-win-core-file*.dll
    return (_stricmp(dllName, "kernel32.dll") == 0) ||
           (_stricmp(dllName, "kernelbase.dll") == 0) ||
           (_strnicmp(dllName, "api-ms-win-core-file", 20) == 0);
}

// Duyệt PE Header và hook IAT
size_t InstallIATHookInModule(HMODULE hModule, HMODULE hSelfModule)
{
	// Bỏ qua DLL của self/Null
    if (!hModule || hModule == hSelfModule) {
        return 0;
    }

    uintptr_t imageBase = reinterpret_cast<uintptr_t>(hModule);
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    IMAGE_DATA_DIRECTORY importDirectory =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// Nếu không có Import Table thì thoát
    if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0) {
        return 0;
    }

    size_t hookedCount = 0;
    auto importDescriptor =
        reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(imageBase + importDirectory.VirtualAddress);

    for (; importDescriptor->Name != 0; ++importDescriptor) {
        const char* currentDllName =
            reinterpret_cast<const char*>(imageBase + importDescriptor->Name);

		// Chỉ xét các DLL cung cấp CreateFileW, bỏ qua DLL khác
        if (!IsTargetFileApiDll(currentDllName)) {
            continue;
        }

		// FirstThunk trỏ tới IAT (Import Address Table) - bảng chứa con trỏ hàm thực tế
        auto thunkIAT = reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + importDescriptor->FirstThunk);
		// OriginalFirstThunk trỏ tới INT (Import Name Table) - bảng chứa tên hàm
        PIMAGE_THUNK_DATA thunkINT = importDescriptor->OriginalFirstThunk
            ? reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + importDescriptor->OriginalFirstThunk)
            : thunkIAT;

        for (; thunkIAT->u1.Function != 0; ++thunkIAT, ++thunkINT) {
			// Bỏ qua import theo Ordinal, chỉ xét import theo Tên
            if (IMAGE_SNAP_BY_ORDINAL(thunkINT->u1.Ordinal)) {
                continue;
            }
            auto importByName =
                reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBase + thunkINT->u1.AddressOfData);

			// Nếu là CreateFileW thì tráo con trỏ trong IAT sang HookedCreateFileW
            if (std::strcmp(importByName->Name, "CreateFileW") == 0) {
                uintptr_t currentFunc = static_cast<uintptr_t>(thunkIAT->u1.Function);
                uintptr_t hookAddr = reinterpret_cast<uintptr_t>(HookedCreateFileW);

                if (currentFunc == hookAddr) {
                    continue;
                }

                DWORD oldProtect = 0;
                if (VirtualProtect(&thunkIAT->u1.Function, sizeof(uintptr_t),
                                   PAGE_READWRITE, &oldProtect)) {
                    thunkIAT->u1.Function = hookAddr;
                    VirtualProtect(&thunkIAT->u1.Function, sizeof(uintptr_t),
                                   oldProtect, &oldProtect);

					// Lưu lại ô IAT đã bị tráo
                    EnterCriticalSection(&g_Lock);
                    g_HookedSlots.push_back({
                        reinterpret_cast<uintptr_t*>(&thunkIAT->u1.Function),
                        currentFunc
                    });
                    LeaveCriticalSection(&g_Lock);

                    ++hookedCount;
                }
            }
        }
    }

    return hookedCount;
}

// Khôi phục toàn bộ ô IAT đã sửa khi DLL bị unload
void UninstallAllIATHooks()
{
	// Duyệt danh sách g_HookedSlots và khôi phục con trỏ hàm gốc
    EnterCriticalSection(&g_Lock);
    for (const HookedSlot& slot : g_HookedSlots) {
        DWORD oldProtect = 0;
        if (VirtualProtect(slot.iatEntry, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect)) {
            *slot.iatEntry = slot.originalAddr;
            VirtualProtect(slot.iatEntry, sizeof(uintptr_t), oldProtect, &oldProtect);
        }
    }
    g_HookedSlots.clear();
    LeaveCriticalSection(&g_Lock);
}

// Thread khởi tạo hook (tách khỏi DllMain để tránh Loader Lock)
DWORD WINAPI InitHookThread(LPVOID lpParam)
{
    HMODULE hSelfModule = reinterpret_cast<HMODULE>(lpParam);

    // Đường dẫn file log trong thư mục %TEMP% của tiến trình
    DWORD tempLen = GetTempPathW(static_cast<DWORD>(std::size(g_LogFilePath)), g_LogFilePath);
    if (tempLen > 0 && tempLen + 24 < std::size(g_LogFilePath)) {
        wcscat_s(g_LogFilePath, L"notepad_iat_hook.log");
    } else {
        g_LogFilePath[0] = L'\0';
    }

    // Lấy địa chỉ hàm CreateFileW từ kernelbase.dll trước khi sửa IAT.
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

	// Nếu không lấy được từ kernelbase.dll thì thử lấy từ kernel32.dll
    if (hKernelBase) {
        g_OriginalCreateFileW = reinterpret_cast<pfnCreateFileW>(
            GetProcAddress(hKernelBase, "CreateFileW")
        );
    }
    if (!g_OriginalCreateFileW && hKernel32) {
        g_OriginalCreateFileW = reinterpret_cast<pfnCreateFileW>(
            GetProcAddress(hKernel32, "CreateFileW")
        );
    }
    if (!g_OriginalCreateFileW) {
        return 1;
    }

    // Duyệt tất cả các module đang nạp trong tiến trình mục tiêu để patch IAT
    // (Bỏ qua chính DLL của selfmodule và kernelbase.dll)
    size_t totalHooked = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32W me{}; // Khởi tạo struct MODULEENTRY32W chứa thông tin module
		me.dwSize = sizeof(me); // Khởi tạo dwSize trước khi gọi Module32FirstW/Module32NextW
        if (Module32FirstW(hSnap, &me)) {
            do {
                if (me.hModule == hKernelBase) {
                    continue;
                }
                totalHooked += InstallIATHookInModule(me.hModule, hSelfModule);
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
    }

    std::wstring initMsg = L"[IAT Hook] Da cai dat CreateFileW hook trong PID " +
                           std::to_wstring(GetCurrentProcessId()) +
                           L" (so IAT slot da patch: " + std::to_wstring(totalHooked) + L")\r\n";
    WriteHookLog(initMsg);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    // Chạy ngay khi DLL vừa được nạp vào tiến trình
    case DLL_PROCESS_ATTACH: 
        DisableThreadLibraryCalls(hModule); // không cần gọi DllMain với DLL_THREAD_ATTACH / DLL_THREAD_DETACH
        InitializeCriticalSection(&g_Lock); // Tạo khóa đồng bộ
        g_LockInitialized = true;

        // Tạo Thread riêng để hook
        if (HANDLE hThread = CreateThread(nullptr, 0, InitHookThread, hModule, 0, nullptr)) {
            CloseHandle(hThread);
        }
        break;
    
    // Chạy khi DLL bị gỡ
    case DLL_PROCESS_DETACH:
        if (g_LockInitialized) {
            if (lpReserved == nullptr) {
                UninstallAllIATHooks();
            }
            DeleteCriticalSection(&g_Lock);
            g_LockInitialized = false;
        }
        break;
    }
    return TRUE;
}
