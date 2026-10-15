#include <iostream>
#include <windows.h>
#include <fltUser.h>
#include "../SharedMinifilter.h"

// Đảm bảo liên kết fltLib.lib
#pragma comment(lib, "fltLib.lib")

int main()
{
    // Cài đặt console hỗ trợ UTF-8
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "  Minifilter File & Process Activity Monitor (User Mode Client) \n";

    std::wcout << L"[*] Dang ket noi toi communication port: " << MINIFILTER_PORT_NAME << L" ...\n";

    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hr = FilterConnectCommunicationPort(
        MINIFILTER_PORT_NAME,
        0,
        NULL,
        0,
        NULL,
        &hPort
    );

    if (FAILED(hr)) {
        std::cerr << "[-] Khong the ket noi toi Minifilter Port. HRESULT: 0x" << std::hex << hr << std::dec << "\n";
        std::cerr << "    -> Hay chac chan MinifilterDriver da duoc load ('fltmc load MinifilterDriver').\n";
        std::cerr << "    -> Hay chay chuong trinh duoi quyen Administrator!\n\n";
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Ket noi toi Minifilter Communication Port thanh cong!\n";
    std::cout << "[*] Dang lang nghe cac su kien he thong...\n";
    std::cout << "--------------------------------------------------------------\n";

    MONITOR_MESSAGE msg = { 0 };

    while (true) {
        RtlZeroMemory(&msg, sizeof(msg));

        // Nhận event từ Driver qua FilterGetMessage
        hr = FilterGetMessage(
            hPort,
            &msg.MessageHeader,
            sizeof(msg),
            NULL
        );

        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                std::cout << "[-] Port bi ngat ket noi boi driver.\n";
            } else {
                std::cerr << "[-] FilterGetMessage that bai. HRESULT: 0x" << std::hex << hr << std::dec << "\n";
            }
            break;
        }

        PMONITOR_EVENT pEvent = &msg.Event;

        switch (pEvent->EventType) {
        case EVENT_FILE_CREATE:
            std::wcout << L"[FILE_CREATE]  PID: " << pEvent->ProcessId
                       << L" | Target: " << pEvent->TargetPath << L"\n";
            break;

        case EVENT_FILE_MODIFY:
            std::wcout << L"[FILE_MODIFY]  PID: " << pEvent->ProcessId
                       << L" | Target: " << pEvent->TargetPath << L"\n";
            break;

        case EVENT_FILE_DELETE:
            std::wcout << L"[FILE_DELETE]  PID: " << pEvent->ProcessId
                       << L" | Target: " << pEvent->TargetPath << L"\n";
            break;

        case EVENT_PROCESS_CREATE:
            std::wcout << L"[PROC_CREATE]  New PID: " << pEvent->ProcessId
                       << L" (Parent PID: " << pEvent->ParentProcessId << L")"
                       << L" | Image: " << pEvent->TargetPath << L"\n";
            break;

        case EVENT_PROCESS_EXIT:
            std::wcout << L"[PROC_EXIT]    PID: " << pEvent->ProcessId << L"\n";
            break;

        default:
            break;
        }
    }

    CloseHandle(hPort);
    return 0;
}
