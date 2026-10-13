# Hướng Dẫn Thực Hành: User-Mode Hooking (IAT Hook & Inline Hook)

Giải pháp này sử dụng **1 Solution chứa 2 Project riêng biệt** trong Visual Studio:
- **`IATHook_Demo`**: Dự án thực hành kỹ thuật **IAT (Import Address Table) Hooking**.
- **`InlineHook_Demo`**: Dự án thực hành kỹ thuật **Inline Hooking (Code Patching)** hỗ trợ cả kiến trúc 32-bit (x86) và 64-bit (x64).

---

## 1. Cấu Trúc Thư Mục

```text
Hook_UserMode/
│
├── Hook_UserMode.sln           <-- File Solution mở bằng Visual Studio
│
├── IATHook_Demo/
│   ├── IATHook_Demo.vcxproj   <-- Project cấu hình cho IAT Hook
│   └── main.cpp               <-- Mã nguồn cài đặt duyệt PE Header & hoán đổi IAT
│
└── InlineHook_Demo/
    ├── InlineHook_Demo.vcxproj <-- Project cấu hình cho Inline Hook
    └── main.cpp               <-- Mã nguồn ghi đè Opcodes (JMP patch) & phục hồi bytes
```

---

## 2. Cách Mở và Chạy Trên Visual Studio

1. **Mở dự án:**
   - Khởi động **Visual Studio**.
   - Chọn **Open a project or solution**.
   - Trỏ tới file: `c:\Users\Cuong\source\repo\Hook_UserMode\Hook_UserMode.sln`.

2. **Chọn dự án cần chạy (Set as Startup Project):**
   - Trong cửa sổ **Solution Explorer** (bên phải màn hình), nhấp chuột phải vào dự án bạn muốn chạy:
     - Chọn `IATHook_Demo` nếu muốn chạy bài IAT Hook.
     - Chọn `InlineHook_Demo` nếu muốn chạy bài Inline Hook.
   - Nhấp chuột phải -> Chọn **Set as Startup Project**.

3. **Chọn cấu hình và kiến trúc:**
   - Thanh công cụ phía trên chọn **Debug** và **x64** (hoặc **x86** tuỳ ý).

4. **Biên dịch và chạy thử:**
   - Nhấn **F5** (hoặc nút **Local Windows Debugger** màu xanh).
   - Quan sát thông báo trên màn hình Console và hộp thoại `MessageBox` bung lên:
     - *Lần 1:* Hiện dialog với text gốc ban đầu.
     - *Lần 2:* Bị can thiệp, nội dung dialog và tiêu đề bị biến đổi thành chuỗi ký tự đã hook!

---

## 3. Bản Chất Kỹ Thuật Từng Bài

### Bài 1: IAT Hooking ([`IATHook_Demo/main.cpp`](file:///c:/Users/Cuong/source/repo/Hook_UserMode/IATHook_Demo/main.cpp))
1. **Duyệt PE Header:**
   - Lấy Base Address từ `GetModuleHandleA(NULL)`.
   - Lần lượt truy cập `IMAGE_DOS_HEADER` -> `IMAGE_NT_HEADERS` -> `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]`.
2. **Dò tìm DLL và hàm:**
   - Lặp qua mảng `IMAGE_IMPORT_DESCRIPTOR` tìm `user32.dll`.
   - Duyệt song song qua `OriginalFirstThunk` (INT - tên hàm) và `FirstThunk` (IAT - con trỏ hàm thực tế) để tìm hàm `MessageBoxA`.
3. **Hoán đổi con trỏ:**
   - Dùng `VirtualProtect(&thunkIAT->u1.Function, ..., PAGE_READWRITE, ...)` để mở quyền ghi nhớ.
   - Lưu địa chỉ hàm gốc vào biến con trỏ toàn cục `g_OriginalMessageBoxA`.
   - Gán `thunkIAT->u1.Function = (uintptr_t)HookedMessageBoxA`.
   - Khôi phục lại cờ bảo vệ bộ nhớ.

---

### Bài 2: Inline Hooking ([`InlineHook_Demo/main.cpp`](file:///c:/Users/Cuong/source/repo/Hook_UserMode/InlineHook_Demo/main.cpp))
1. **Lấy địa chỉ hàm gốc:**
   - Dùng `GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA")`.
2. **Sao chép Opcodes:**
   - Lưu 14 bytes (trên x64) hoặc 5 bytes (trên x86) đầu tiên của hàm gốc vào mảng `g_OriginalBytes`.
3. **Tạo lệnh nhảy (Detour Patch):**
   - **x64 (14 bytes absolute jump):**
     ```asm
     mov rax, <64_bit_target_address>   ; 48 B8 + 8 bytes địa chỉ
     jmp rax                            ; FF E0
     ```
   - **x86 (5 bytes relative jump):**
     ```asm
     jmp <relative_offset>              ; E9 + 4 bytes độ lệch (HookAddr - (TargetAddr + 5))
     ```
4. **Patch bộ nhớ:**
   - Dùng `VirtualProtect` cấp quyền `PAGE_EXECUTE_READWRITE`.
   - Ghi đè cấu trúc Jump Patch vào địa chỉ hàm gốc.
   - Khôi phục quyền và gọi `FlushInstructionCache()` để CPU xóa bộ đệm lệnh cũ.
5. **Gọi hàm gốc mà không lặp vô hạn:**
   - Tạm thời khôi phục lại các byte gốc (`memcpy(g_TargetFunction, g_OriginalBytes, ...)`).
   - Gọi lại `MessageBoxA`.
   - Patch lại ngay sau khi hoàn tất.
