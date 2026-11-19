#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <iostream>
#include <iterator>
#include <string>

#pragma comment(lib, "User32.lib")

// Handle của hook toàn cục WH_KEYBOARD_LL
HHOOK g_KeyboardHook = nullptr;

// Hàm kiểm tra vkCode là phím bổ trợ (modifier)
bool IsModifierKey(DWORD vkCode)
{
    switch (vkCode) {
    case VK_SHIFT:
    case VK_LSHIFT:
    case VK_RSHIFT:
    case VK_CONTROL:
    case VK_LCONTROL:
    case VK_RCONTROL:
    case VK_MENU:
    case VK_LMENU:
    case VK_RMENU:
    case VK_LWIN:
    case VK_RWIN:
    case VK_CAPITAL:
        return true;
    default:
        return false;
    }
}

// Lấy tên phím vật lý bằng GetKeyNameTextW
std::wstring GetPhysicalKeyNameW(const KBDLLHOOKSTRUCT* kb)
{
    // Tạo lParam truyền vào GetKeyNameTextW:
    // - Bit 16..23: scan code
    // - Bit 24:     cờ extended key
    LONG lParam = static_cast<LONG>((kb->scanCode & 0xFF) << 16); // giữ lại 8 bit thấp của scancode và dịch lên vị trí bit 16..23
    // Kiểm tra cờ phím mở rộng
    if (kb->flags & LLKHF_EXTENDED) {
        lParam |= (1 << 24); // Bật bit 24 lên 1
    }

    // Lấy keyName (Unicode)
    wchar_t keyName[64] = { 0 };
    if (GetKeyNameTextW(lParam, keyName, static_cast<int>(std::size(keyName))) > 0) {
        return std::wstring(keyName);
    }

    // Nếu không lấy được tên -> in ra vkcode 
    wchar_t fallback[32] = { 0 };
    std::swprintf(fallback, std::size(fallback), L"VK_0x%02lX", kb->vkCode);
    return std::wstring(fallback);
}

// Dịch phím nhấn sang ký tự Unicode
std::wstring ResolveKeyOutputW(const KBDLLHOOKSTRUCT* kb, bool isKeyDown)
{
    // 1. Khi nhả phím hoặc chính phím đang nhấn là phím bổ trợ -> dùng tên vật lý
    if (!isKeyDown || IsModifierKey(kb->vkCode)) {
        return GetPhysicalKeyNameW(kb);
    }

    // 2. Ngoại lệ VK_PACKET (ký tự Unicode bởi hàm SendInput, như từ Unikey)
    if (kb->vkCode == VK_PACKET) {
        // In trực tiếp ký tự unicode
        wchar_t ch = static_cast<wchar_t>(kb->scanCode);
        if (ch >= 0x20 && ch != 0x7F) {
            return std::wstring(1, ch);
        }
        return L"VK_PACKET";
    }

    // 3. Kiểm tra cờ trạng thái các phím bổ trợ
    // Cở ở bit cao
    const bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    const bool ctrlDown  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    const bool altDown   = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0 || (kb->flags & LLKHF_ALTDOWN) != 0;
    const bool winDown   = ((GetAsyncKeyState(VK_LWIN) & 0x8000) != 0) ||
                           ((GetAsyncKeyState(VK_RWIN) & 0x8000) != 0);
    // Cờ ở bit thấp
    const bool capsOn    = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

    // 4. Ngoại lệ khi đang đè Ctrl / Alt / Win
    //    KHÔNG gọi ToUnicodeEx 
    if (ctrlDown || altDown || winDown) {
        std::wstring combo;
        if (ctrlDown)  combo += L"Ctrl + ";
        if (altDown)   combo += L"Alt + ";
        if (winDown)   combo += L"Win + ";
        if (shiftDown) combo += L"Shift + ";
        combo += GetPhysicalKeyNameW(kb);
        return combo;
    }

    // 5. Phím khoảng trắng: hiển thị tên thay dấu cách
    if (kb->vkCode == VK_SPACE) {
        return GetPhysicalKeyNameW(kb);
    }

    // 6. Mảng trạng thái keyState[256] cho ToUnicodeEx
    BYTE keyState[256] = { 0 };
    if (shiftDown) {
        keyState[VK_SHIFT] = 0x80;
    }
    if (capsOn) {
        keyState[VK_CAPITAL] = 0x01;
    }

    // Lấy Keyboard Layout của cửa sổ đang mở trên cùng
    HWND fgWindow = GetForegroundWindow();
    DWORD fgThreadId = fgWindow ? GetWindowThreadProcessId(fgWindow, nullptr) : 0; // Chỉ lấy threadID
    HKL layout = GetKeyboardLayout(fgThreadId);

    wchar_t unicodeBuf[8] = { 0 }; // Mảng chứa kết quả unicode
 
    int len = ToUnicodeEx(
        kb->vkCode,
        kb->scanCode,
        keyState,
        unicodeBuf,
        static_cast<int>(std::size(unicodeBuf)),
        0x04, // Cờ 0x04: không làm thay đổi trạng thái dead-key 
        layout
    );

    // Lấy kết quả nếu ToUnicodeEx trả về ký tự không phải ký tự điều khiển < 0x20 hay 0x7F (del)
    if (len > 0 && unicodeBuf[0] >= 0x20 && unicodeBuf[0] != 0x7F) {
        return std::wstring(unicodeBuf, len);
    }

    // 7. Fallback cho phím điều khiển / chức năng (Enter, Esc, Backspace, Tab, F1..F12, mũi tên...) hoặc dead-key
    return GetPhysicalKeyNameW(kb);
}

// Hàm callback xử lý sự kiện bàn phím ở mức Low-Level
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // Nếu nCode < 0, chuyển cho hook kế tiếp
    if (nCode == HC_ACTION) {
        const auto* kb = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);

        const bool isKeyDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
        const bool isKeyUp   = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);

        if (isKeyDown || isKeyUp) {
            const wchar_t* eventName = isKeyDown ? L"KEY_DOWN" : L"KEY_UP  ";

            std::wstring keyDisplay = ResolveKeyOutputW(kb, isKeyDown);
            const wchar_t* injectedTag = (kb->flags & LLKHF_INJECTED) ? L" [INJECTED]" : L""; // Kiểm tra cờ giả lập phím

            std::wcout << L"[WH_KEYBOARD_LL] " << eventName
                       << L" | Phim: " << keyDisplay
                       << L" (VK=0x" << std::hex << std::uppercase << kb->vkCode
                       << L", Scan=0x" << kb->scanCode << std::dec << L")"
                       << injectedTag << L'\n';

            // Chặn phím F9, không cho ứng dụng đích nhận
            if (kb->vkCode == VK_F9) {
                if (isKeyDown) {
                    std::wcout << L"  -> [BLOCKED] Da chan F9!\n";
                }
                return 1; // Trả về khác 0 để nuốt sự kiện phím
            }

            // Nhấn ESC để thoát Message Loop và gỡ hook
            if (isKeyDown && kb->vkCode == VK_ESCAPE) {
                std::wcout << L"  -> Nhan ESC, dang thoat...\n";
                PostQuitMessage(0);
            }
        }
    }

    // Chuyển tiếp sự kiện cho hook tiếp theo trong chuỗi (và tới ứng dụng đích)
    return CallNextHookEx(g_KeyboardHook, nCode, wParam, lParam);
}

// Cài đặt Low-Level Keyboard Hook
bool InstallKeyboardHook()
{
    g_KeyboardHook = SetWindowsHookExW(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        GetModuleHandleW(nullptr),
        0
    );

    if (!g_KeyboardHook) {
        std::wcerr << L"[-] SetWindowsHookExW that bai! Ma loi: " << GetLastError() << L'\n';
        return false;
    }

    std::wcout << L"Da cai dat WH_KEYBOARD_LL\n";
    return true;
}

// Gỡ bỏ Hook
void UninstallKeyboardHook()
{
    if (g_KeyboardHook) {
        UnhookWindowsHookEx(g_KeyboardHook);
        g_KeyboardHook = nullptr;
        std::wcout << L"Da go WH_KEYBOARD_LL.\n";
    }
}

int main()
{
    // Thiết lập chế độ UTF-16 cho stdout/stderr để std::wcout in chuẩn ký tự Unicode
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    if (!InstallKeyboardHook()) {
        return 1;
    }

    std::wcout << L"\nDang lang nghe ban phim:\n";
    // WH_KEYBOARD_LL phải có Message Loop để Windows gọi callback
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    UninstallKeyboardHook();

    return 0;
}
