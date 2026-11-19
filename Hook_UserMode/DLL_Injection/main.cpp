#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Advapi32.lib")

// Tìm PID đầu tiên của tiến trình theo tên 
DWORD FindProcessIdByName(const wchar_t* processName)
{
    // Chụp snapshot tiến trình
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe{}; // Khởi tạo struct chứa thông tin proc
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

// Kiểm tra DLL đã xuất hiện trong danh sách module của tiến trình đích hay chưa
bool IsModuleLoadedInProcess(DWORD pid, const wchar_t* dllFileName)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;

    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllFileName) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    return found;
}

// Lấy đường dẫn đầy đủ tới HookPayload.dll nằm cùng thư mục với Injector .exe
std::wstring GetPayloadDllPath()
{
    wchar_t exePath[MAX_PATH] = { 0 };
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return L"";
    }

    std::wstring path(exePath, len);
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return L"HookPayload.dll";
    }
    return path.substr(0, pos + 1) + L"HookPayload.dll";
}

// Cấp quyền đọc + thực thi cho ALL APPLICATION PACKAGES (S-1-15-2-1)
// để tránh lỗi ACCESS_DENIED khi inject vào Notepad bản Windows 11 (AppContainer/Packaged)
void GrantAppContainerReadExecute(const std::wstring& filePath)
{
    PSID appPkgSid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-15-2-1", &appPkgSid)) {
        return;
    }

    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, &oldDacl, nullptr, &pSD) == ERROR_SUCCESS) {
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(appPkgSid);

        PACL newDacl = nullptr;
        if (SetEntriesInAclW(1, &ea, oldDacl, &newDacl) == ERROR_SUCCESS) {
            SetNamedSecurityInfoW(const_cast<LPWSTR>(filePath.c_str()), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION,
                                  nullptr, nullptr, newDacl, nullptr);
            LocalFree(newDacl);
        }
        LocalFree(pSD);
    }

    LocalFree(appPkgSid);
}

// Thực hiện DLL Injection bằng VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW)
bool InjectDLL(DWORD pid, const std::wstring& dllPath)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    if (!hProcess) {
        std::wcerr << L"[-] OpenProcess that bai! Ma loi: " << GetLastError() << L'\n';
        return false;
    }

    const size_t pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::wcerr << L"[-] VirtualAllocEx that bai! Ma loi: " << GetLastError() << L'\n';
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), pathSize, nullptr)) {
        std::wcerr << L"[-] WriteProcessMemory that bai! Ma loi: " << GetLastError() << L'\n';
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibraryW = hKernel32
        ? reinterpret_cast<LPVOID>(GetProcAddress(hKernel32, "LoadLibraryW"))
        : nullptr;
    if (!pLoadLibraryW) {
        std::wcerr << L"[-] Khong lay duoc dia chi LoadLibraryW!\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW),
        remoteMem,
        0,
        nullptr
    );
    if (!hThread) {
        std::wcerr << L"[-] CreateRemoteThread that bai! Ma loi: " << GetLastError() << L'\n';
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, 5000);

    // Dọn bộ nhớ đường dẫn trong tiến trình đích
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return IsModuleLoadedInProcess(pid, L"HookPayload.dll");
}

int wmain(int argc, wchar_t* argv[])
{
    const wchar_t* targetProcName = (argc >= 2) ? argv[1] : L"notepad.exe";

    std::wstring dllPath = GetPayloadDllPath();
    if (dllPath.empty() || GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"[-] Khong tim thay HookPayload.dll tai: " << dllPath << L'\n';
        return 1;
    }

    GrantAppContainerReadExecute(dllPath);

    std::wcout << L"[1] Dang tim tien trinh: " << targetProcName << L"...\n";
    DWORD pid = FindProcessIdByName(targetProcName);

    // Nếu chưa thấy notepad.exe đang chạy thì tự khởi chạy bản System32 để demo
    if (pid == 0 && _wcsicmp(targetProcName, L"notepad.exe") == 0) {
        std::wcout << L"[*] Chua thay notepad.exe, dang khoi chay notepad.exe...\n";
        STARTUPINFOW si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);
        wchar_t cmd[] = L"notepad.exe";
        if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            WaitForInputIdle(pi.hProcess, 3000);
            for (int attempt = 0; attempt < 10 && pid == 0; ++attempt) {
                Sleep(200);
                pid = FindProcessIdByName(L"notepad.exe");
            }
            if (pid == 0) {
                pid = pi.dwProcessId;
            }
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    if (pid == 0) {
        std::wcerr << L"[-] Khong tim thay tien trinh " << targetProcName << L"!\n";
        return 1;
    }

    std::wcout << L"[2] Da tim thay PID = " << pid << L'\n';
    std::wcout << L"    DLL Path: " << dllPath << L'\n';

    if (IsModuleLoadedInProcess(pid, L"HookPayload.dll")) {
        std::wcout << L"[!] HookPayload.dll da duoc nap vao tien trinh nay truoc do.\n";
    } else {
        std::wcout << L"[3] Dang inject HookPayload.dll vao tien trinh...\n";
        if (!InjectDLL(pid, dllPath)) {
            std::wcerr << L"[-] Inject that bai! (Kiem tra bitness x64/Win32 hoac quyen Admin)\n";
            return 1;
        }
        std::wcout << L"[+] Inject thanh cong! IAT Hook CreateFileW da duoc cai dat.\n";
    }

    wchar_t tempPath[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempPath);
    std::wcout << L"\n[Huong dan test tren Notepad]\n";
    std::wcout << L"  1. Thu mo (Ctrl+O) hoac luu (Ctrl+S) file trong Notepad.\n";
    std::wcout << L"  2. Xem log CreateFileW tai: " << tempPath << L"notepad_iat_hook.log\n";
    std::wcout << L"     (Hoac mo DebugView de xem OutputDebugStringW).\n";
    std::wcout << L"  3. Thu luu/mo file ten 'block_test.txt' de xem hook chan CreateFileW!\n";

    std::wcin.get();
    return 0;
}
