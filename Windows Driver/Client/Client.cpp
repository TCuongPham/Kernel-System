#include <iostream>
#include <windows.h>
#include "../Shared.h"

int main()
{
    std::cout << "===========================================\n";
    std::cout << "  Legacy Driver IRP Communication Client   \n";
    std::cout << "===========================================\n\n";

    // 1. Mở Handle tới Driver thông qua Symbolic Link
    std::wcout << L"[*] Dang ket noi toi driver qua: " << USER_DEVICE_NAME << L" ...\n";

    HANDLE hDevice = CreateFileW(
        USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,              // Khong chia se
        NULL,           // Security attributes
        OPEN_EXISTING,  // Bat buoc mo device da ton tai
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cerr << "[-] Khong the ket noi toi driver. Error code: " << error << "\n";
        if (error == ERROR_FILE_NOT_FOUND) {
            std::cerr << "    -> Driver chua duoc nap hoac chua chay (dung 'sc start LegacyDriver').\n";
        } else if (error == ERROR_ACCESS_DENIED) {
            std::cerr << "    -> Quyen truy cap bi tu choi. Hay chay chuong trinh duoi quyen Administrator!\n";
        }
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Ket noi toi Driver thanh cong!\n\n";

    // 2. Test IOCTL 1: Lay tin nhan Hello World tu Kernel
    {
        std::cout << "[1] Gui lenh IOCTL_LEGACY_HELLOWORLD xuong driver...\n";
        char buffer[128] = { 0 };
        DWORD bytesReturned = 0;

        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_LEGACY_HELLOWORLD,
            NULL,
            0,
            buffer,
            sizeof(buffer),
            &bytesReturned,
            NULL
        );

        if (success) {
            std::cout << "    -> Kernel phan hoi: \"" << buffer << "\" (" << bytesReturned << " bytes)\n\n";
        } else {
            std::cerr << "    [-] DeviceIoControl that bai. Error: " << GetLastError() << "\n\n";
        }
    }

    // 3. Test IOCTL 2: Gui yeu cau tinh toan (Truyen struct qua lai)
    {
        CALC_REQUEST req = { 123, 456 };
        CALC_RESPONSE resp = { 0 };
        DWORD bytesReturned = 0;

        std::cout << "[2] Gui lenh IOCTL_LEGACY_ADD_NUMBERS (tinh tong " << req.a << " + " << req.b << ")...\n";

        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_LEGACY_ADD_NUMBERS,
            &req,
            sizeof(req),
            &resp,
            sizeof(resp),
            &bytesReturned,
            NULL
        );

        if (success) {
            std::cout << "    -> Kernel tinh toan ket qua: " << resp.result << "\n\n";
        } else {
            std::cerr << "    [-] DeviceIoControl that bai. Error: " << GetLastError() << "\n\n";
        }
    }

    // 4. Dong Handle
    CloseHandle(hDevice);
    std::cout << "[*] Da dong handle toi driver. Ket thuc.\n";
    std::cin.get();

    return 0;
}
