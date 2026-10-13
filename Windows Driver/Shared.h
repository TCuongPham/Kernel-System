#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// Đường dẫn tên thiết bị trong Kernel và Symbolic Link
#define DEVICE_NAME         L"\\Device\\LegacyDriverDevice"
#define SYMBOLIC_LINK_NAME  L"\\DosDevices\\LegacyDriverLink"
#define USER_DEVICE_NAME    L"\\\\.\\LegacyDriverLink"

// Định nghĩa mã IOCTL:
// DeviceType: FILE_DEVICE_UNKNOWN (0x22)
// Function: 0x800 -> 0xFFF (vùng dành riêng cho custom drivers)
// Method: METHOD_BUFFERED (I/O Manager cấp phát bộ đệm an toàn 2 chiều qua SystemBuffer)
// Access: FILE_ANY_ACCESS

#define IOCTL_LEGACY_HELLOWORLD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_LEGACY_ADD_NUMBERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Cấu trúc dữ liệu minh họa tính toán (User gửi a, b -> Driver trả về kết quả a + b)
typedef struct _CALC_REQUEST {
    int a;
    int b;
} CALC_REQUEST, *PCALC_REQUEST;

typedef struct _CALC_RESPONSE {
    int result;
} CALC_RESPONSE, *PCALC_RESPONSE;
