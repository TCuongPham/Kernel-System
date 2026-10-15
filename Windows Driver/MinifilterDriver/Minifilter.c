#include <fltKernel.h>
#include <dontuse.h>
#include "../SharedMinifilter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT   gServerPort = NULL;
PFLT_PORT   gClientPort = NULL;

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
NTSTATUS MinifilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Thông báo kết nối Communication Port
NTSTATUS PortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie);
VOID PortDisconnectNotify(_In_opt_ PVOID ConnectionCookie);

// Bắt sự kiện TẠO FILE (IRP_MJ_CREATE)
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

// Bắt sự kiện SỬA FILE (IRP_MJ_WRITE)
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

// Bắt sự kiện XÓA FILE (IRP_MJ_SET_INFORMATION)
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

// Bắt sự kiện TẠO/EXIT PROCESS - Kernel Callback của Windows Subsystem (PsSetCreateProcessNotifyRoutineEx).
VOID ProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

// Bảng đăng ký các thao tác I/O cần chặn
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreCreateCallback,
      PostCreateCallback },

    { IRP_MJ_WRITE,
      0,
      PreWriteCallback,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      PreSetInformationCallback,
      NULL },

    { IRP_MJ_OPERATION_END }
};

// Đăng ký bộ lọc với Filter Manager
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // Context
    Callbacks,                          // Operation callbacks
    MinifilterUnload,                   // FilterUnloadCallback
    NULL,                               // InstanceSetupCallback
    NULL,                               // InstanceQueryTeardownCallback
    NULL,                               // InstanceTeardownStartCallback
    NULL,                               // InstanceTeardownCompleteCallback
    NULL,                               // GenerateFileNameCallback
    NULL,                               // NormalizeNameComponentCallback
    NULL                                // NormalizeContextCleanupCallback
};

/**
 * @brief Gửi thông điệp sự kiện lên ứng dụng User Mode qua FltSendMessage
 */
VOID SendEventToUserMode(PMONITOR_EVENT Event)
{
    // Kiểm tra điều kiện
    if (gClientPort == NULL || gFilterHandle == NULL) {
        return;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -100000; // 10ms timeout để tránh block kernel I/O

    __try {
        FltSendMessage(
            gFilterHandle,
            &gClientPort,
            Event,
            sizeof(MONITOR_EVENT),
            NULL,
            NULL,
            &timeout
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Bỏ qua ngoại lệ nếu cổng đột ngột ngắt kết nối
    }
}

/**
 * @brief Lấy đường dẫn file từ CallbackData
 */
VOID GetFilePath(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(MAX_PATH_LEN) PWCHAR Buffer)
{
    Buffer[0] = L'\0';
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	// Lấy thông tin tên file từ CallbackData
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (NT_SUCCESS(status) && nameInfo != NULL) {
        // Tách các thành phần của đường dẫn (Volume, Directory, Name, Extension)
        FltParseFileNameInformation(nameInfo);

        USHORT copyLength = nameInfo->Name.Length / sizeof(WCHAR);
        if (copyLength >= MAX_PATH_LEN) {
            copyLength = MAX_PATH_LEN - 1;
        }
        // Sao chép chuỗi Unicode vào Buffer đầu ra
        RtlCopyMemory(Buffer, nameInfo->Name.Buffer, copyLength * sizeof(WCHAR));
        Buffer[copyLength] = L'\0';

		// Giải phóng thông tin tên file
        FltReleaseFileNameInformation(nameInfo);
    }
}

// ======================= FILE SYSTEM CALLBACKS =======================

FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    // Cần PostCreate để biết file có thực sự được tạo thành công không
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Kiểm tra xem file có thực sự được TẠO MỚI không
    ULONG_PTR information = Data->IoStatus.Information;
    if (information == FILE_CREATED || information == FILE_OVERWRITTEN || information == FILE_SUPERSEDED) {
        MONITOR_EVENT event = { 0 };
        event.EventType = EVENT_FILE_CREATE;
        event.ProcessId = HandleToULong(PsGetCurrentProcessId());

		// Lấy đường dẫn file từ CallbackData
        GetFilePath(Data, event.TargetPath);

		// Gửi sự kiện lên User Mode
        if (event.TargetPath[0] != L'\0') {
            SendEventToUserMode(&event);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Bắt hành vi SỬA FILE (Ghi dữ liệu)
    if (Data->RequestorMode == UserMode) {
        MONITOR_EVENT event = { 0 };
        event.EventType = EVENT_FILE_MODIFY;
        event.ProcessId = HandleToULong(PsGetCurrentProcessId());

        GetFilePath(Data, event.TargetPath);

        if (event.TargetPath[0] != L'\0') {
            SendEventToUserMode(&event);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

#ifndef FileDispositionInformationEx
#define FileDispositionInformationEx ((FILE_INFORMATION_CLASS)64)
#endif

#ifndef FILE_DISPOSITION_FLAG_DELETE
#define FILE_DISPOSITION_FLAG_DELETE 0x00000001
#endif

typedef struct _MY_FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} MY_FILE_DISPOSITION_INFORMATION_EX, *PMY_FILE_DISPOSITION_INFORMATION_EX;

FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FILE_INFORMATION_CLASS infoClass = 
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // Bắt hành vi XÓA FILE
    BOOLEAN isDelete = FALSE;
    PVOID infoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (infoBuffer != NULL) {
        if (infoClass == FileDispositionInformation) {
            PFILE_DISPOSITION_INFORMATION info = (PFILE_DISPOSITION_INFORMATION)infoBuffer;
            if (info->DeleteFile) {
                isDelete = TRUE;
            }
        } else if (infoClass == FileDispositionInformationEx) {
            PMY_FILE_DISPOSITION_INFORMATION_EX infoEx = (PMY_FILE_DISPOSITION_INFORMATION_EX)infoBuffer;
            if (BooleanFlagOn(infoEx->Flags, FILE_DISPOSITION_FLAG_DELETE)) {
                isDelete = TRUE;
            }
        }
    }

    if (isDelete) {
        MONITOR_EVENT event = { 0 };
        event.EventType = EVENT_FILE_DELETE;
        event.ProcessId = HandleToULong(PsGetCurrentProcessId());

        GetFilePath(Data, event.TargetPath);

        if (event.TargetPath[0] != L'\0') {
            SendEventToUserMode(&event);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ======================= PROCESS NOTIFY CALLBACK =======================

VOID ProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    MONITOR_EVENT event = { 0 };
    event.ProcessId = HandleToULong(ProcessId);

    if (CreateInfo != NULL) {
        // TẠO PROCESS MỚI
        event.EventType = EVENT_PROCESS_CREATE;
        event.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);

        if (CreateInfo->ImageFileName != NULL) {
            USHORT copyLen = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            if (copyLen >= MAX_PATH_LEN) {
                copyLen = MAX_PATH_LEN - 1;
            }
            RtlCopyMemory(event.TargetPath, CreateInfo->ImageFileName->Buffer, copyLen * sizeof(WCHAR));
            event.TargetPath[copyLen] = L'\0';
        }
    } else {
        // EXIT PROCESS
        event.EventType = EVENT_PROCESS_EXIT;
        event.ParentProcessId = 0;
        event.TargetPath[0] = L'\0';
    }

    SendEventToUserMode(&event);
}

// ======================= COMMUNICATION PORT CALLBACKS =======================

NTSTATUS PortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    gClientPort = ClientPort;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Minifilter] Client connected to communication port.\n");
    return STATUS_SUCCESS;
}

VOID PortDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Minifilter] Client disconnected from communication port.\n");
}

// ======================= DRIVER ENTRY & UNLOAD =======================

NTSTATUS MinifilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    // Hủy đăng ký Process notify routine
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);

    // Đóng communication server port
    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    // Hủy đăng ký Filter Manager
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Minifilter] Unloaded successfully.\n");
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Minifilter] DriverEntry starting...\n");

    // 1. Đăng ký Filter với Filter Manager
    NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Minifilter] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    // 2. Thiết lập Security Descriptor và tạo Communication Port
    PSECURITY_DESCRIPTOR sd = NULL;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, MINIFILTER_PORT_NAME);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &oa,
        NULL,
        PortConnectNotify,
        PortDisconnectNotify,
        NULL,
        1 // Cho phep toi da 1 client ket noi
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Minifilter] FltCreateCommunicationPort failed: 0x%08X\n", status);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // 3. Đăng ký Callback theo dõi Tạo/Exit Process
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Minifilter] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // 4. Bắt đầu lắng nghe các sự kiện I/O file system
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Minifilter] FltStartFiltering failed: 0x%08X\n", status);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Minifilter] Driver started successfully and filtering!\n");
    return STATUS_SUCCESS;
}
