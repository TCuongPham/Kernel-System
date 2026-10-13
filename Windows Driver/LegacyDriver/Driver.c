#include <ntddk.h>
#include "../Shared.h"

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH   DispatchCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH   DispatchDeviceControl;

// Hàm Unload của Driver - được gọi khi driver bị dừng (sc stop)
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMBOLIC_LINK_NAME);

    // Xóa symbolic link trước

    IoDeleteSymbolicLink(&symLinkName);

    // Xóa Device Object
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[LegacyDriver] Driver unloaded successfully.\n");
}


// Xử lý IRP_MJ_CREATE (CreateFile) và IRP_MJ_CLOSE (CloseHandle)
NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


// Xử lý IRP_MJ_DEVICE_CONTROL (DeviceIoControl từ User Mode)
NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    switch (controlCode) {
    case IOCTL_LEGACY_HELLOWORLD:
    {
        const char message[] = "Xin chao tu Legacy Kernel Driver!";
        ULONG messageLen = (ULONG)strlen(message) + 1;

        if (outBufferLength >= messageLen && systemBuffer != NULL) {
            RtlCopyMemory(systemBuffer, message, messageLen);
            bytesReturned = messageLen;
            status = STATUS_SUCCESS;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[LegacyDriver] IOCTL_LEGACY_HELLOWORLD processed.\n");
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_LEGACY_ADD_NUMBERS:
    {
        if (inBufferLength >= sizeof(CALC_REQUEST) &&
            outBufferLength >= sizeof(CALC_RESPONSE) &&
            systemBuffer != NULL) 
        {
            PCALC_REQUEST request = (PCALC_REQUEST)systemBuffer;
            int sum = request->a + request->b;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
                "[LegacyDriver] Calculating: %d + %d = %d\n", request->a, request->b, sum);

            PCALC_RESPONSE response = (PCALC_RESPONSE)systemBuffer;
            response->result = sum;
            bytesReturned = sizeof(CALC_RESPONSE);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        bytesReturned = 0;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

/**
 * @brief Điểm khởi đầu của Driver (DriverEntry)
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[LegacyDriver] DriverEntry called.\n");

    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symLinkName, SYMBOLIC_LINK_NAME);

    // 1. Tạo Device Object
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[LegacyDriver] Failed to create device object: 0x%08X\n", status);
        return status;
    }

    // 2. Tạo Symbolic Link để User Mode có thể mở qua "\\.\LegacyDriverLink"
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[LegacyDriver] Failed to create symbolic link: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // 3. Đăng ký các hàm Dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                         = DriverUnload;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[LegacyDriver] Driver loaded and ready.\n");
    return STATUS_SUCCESS;
}
