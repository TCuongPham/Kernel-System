#pragma once

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#else
#include <windows.h>
#include <fltUser.h>
#endif

#define MINIFILTER_PORT_NAME L"\\MinifilterMonitorPort"

typedef enum _MONITOR_EVENT_TYPE {
    EVENT_FILE_CREATE = 1,
    EVENT_FILE_MODIFY,
    EVENT_FILE_DELETE,
    EVENT_PROCESS_CREATE,
    EVENT_PROCESS_EXIT
} MONITOR_EVENT_TYPE;

#define MAX_PATH_LEN 260

typedef struct _MONITOR_EVENT {
    MONITOR_EVENT_TYPE EventType;
    ULONG ProcessId;
    ULONG ParentProcessId;          // Dùng khi tạo process
    WCHAR TargetPath[MAX_PATH_LEN]; // Đường dẫn file hoặc process mục tiêu
} MONITOR_EVENT, *PMONITOR_EVENT;

#ifndef _KERNEL_MODE
// Cấu trúc nhận tin nhắn phía User Mode (bắt buộc có FILTER_MESSAGE_HEADER)
typedef struct _MONITOR_MESSAGE {
    FILTER_MESSAGE_HEADER MessageHeader;
    MONITOR_EVENT Event;
} MONITOR_MESSAGE, *PMONITOR_MESSAGE;
#endif
