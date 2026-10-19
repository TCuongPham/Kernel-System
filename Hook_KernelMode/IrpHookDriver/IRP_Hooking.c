#include <ntddk.h>

// ---------------------------------------------------------------------------
// 1. Khai báo API Undocumented của Kernel 
// ---------------------------------------------------------------------------
extern POBJECT_TYPE* IoDriverObjectType;
NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE PassedAccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID* Object
);

// ---------------------------------------------------------------------------
// 2. Cấu hình & Biến toàn cục
// ---------------------------------------------------------------------------
// Chọn \Driver\Beep 
#define TARGET_DRIVER_NAME L"\\Driver\\Beep"
// Mã IOCTL của Beep driver (phát âm thanh qua loa máy tính)
#define IOCTL_BEEP_SET 0x00010000
static PDRIVER_OBJECT   g_TargetDriverObject = NULL;
static PDRIVER_DISPATCH g_OriginalDeviceControl = NULL;

#define DebugLog(Format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, ##__VA_ARGS__)

// Biến đếm số luồng đang chạy trong Hook (Bảo vệ chống BSOD khi Unload)
static volatile LONG    g_ActiveCallCount = 0;

// ---------------------------------------------------------------------------
// 3. Hàm Hook Dispatch (Chặn và xử lý IRP)
// ---------------------------------------------------------------------------
NTSTATUS HookedDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // Báo hiệu: Có 1 luồng đi vào hàm hook
    InterlockedIncrement(&g_ActiveCallCount);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    // In thông tin IOCTL bắt được ra DebugView
    DebugLog("[IRP_HOOK] Catched IRP_MJ_DEVICE_CONTROL! IOCTL: 0x%08X\n", ioctlCode);
    if (ioctlCode == IOCTL_BEEP_SET) {
        DebugLog("[IRP_HOOK] -> Phat hien lenh phat tieng BEEP tu ung dung!\n");
    }
    NTSTATUS status;
    // Chuyển tiếp IRP xuống hàm gốc của driver đích để hệ thống hoạt động bình thường
    if (g_OriginalDeviceControl != NULL) {
        status = g_OriginalDeviceControl(DeviceObject, Irp);
    }
    else {
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        status = STATUS_NOT_SUPPORTED;
    }
    // Báo hiệu: Luồng đã xử lý xong và chuẩn bị rời 
    InterlockedDecrement(&g_ActiveCallCount);
    return status;
}

// ---------------------------------------------------------------------------
// 4. Hàm Unload Driver
// ---------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DebugLog("[IRP_HOOK] Bat dau qua trinh Unhook va Unload driver...\n");

    // Bước 1: Trả lại ngay lập tức con trỏ hàm gốc 
    if (g_TargetDriverObject != NULL && g_OriginalDeviceControl != NULL) {
        InterlockedExchangePointer(
            (PVOID*)&g_TargetDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
            (PVOID)g_OriginalDeviceControl
        );
        DebugLog("[IRP_HOOK] Da tra lai con tro ham goc cho target driver.\n");
    }
    // Bước 2: CHỜ TOÀN BỘ CÁC LUỒNG ĐANG CHẠY TRONG HOOK THOÁT
    // Nếu giải phóng driver khi còn luồng đang chạy => BSOD 
    LARGE_INTEGER interval;
    interval.QuadPart = -10 * 1000 * 50; // Chờ 50ms mỗi vòng
    while (g_ActiveCallCount > 0) {
        DebugLog("[IRP_HOOK] Dang cho %ld luong xu ly xong...\n", g_ActiveCallCount);
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    // Bước 3: Giảm Reference Count để Object Manager dọn dẹp
    if (g_TargetDriverObject != NULL) {
        ObDereferenceObject(g_TargetDriverObject);
        g_TargetDriverObject = NULL;
    }
    DebugLog("[IRP_HOOK] Driver da go bo!\n");
}

// ---------------------------------------------------------------------------
// 5. Entry Point 
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING targetDriverName;

    DebugLog("[IRP_HOOK] DriverEntry: Khoi chay tren Windows...\n");
    DriverObject->DriverUnload = DriverUnload;

    RtlInitUnicodeString(&targetDriverName, TARGET_DRIVER_NAME);
    // Tìm kiếm PDRIVER_OBJECT bằng tên chuẩn
    status = ObReferenceObjectByName(
        &targetDriverName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType, 
        KernelMode,          
        NULL,
        (PVOID*)&g_TargetDriverObject
    );
    if (!NT_SUCCESS(status)) {
        DebugLog("[IRP_HOOK] Khong tim thay Driver Object: 0x%08X\n", status);
        return status;
    }

    DebugLog("[IRP_HOOK] Tim thay Target Driver tai dia chi: 0x%p\n", g_TargetDriverObject);

    // Hoán đổi con trỏ IRP_MJ_DEVICE_CONTROL
    g_OriginalDeviceControl = (PDRIVER_DISPATCH)InterlockedExchangePointer(
        (PVOID*)&g_TargetDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        (PVOID)HookedDeviceControl
    );
    DebugLog("[IRP_HOOK] Hook thanh cong! Con tro goc: 0x%p\n", g_OriginalDeviceControl);
    return STATUS_SUCCESS;
}