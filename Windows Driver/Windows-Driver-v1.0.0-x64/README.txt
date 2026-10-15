========================================================================
             WINDOWS DRIVER PACKAGE (x64 Release)
========================================================================

Goi phat hanh bao gom:
1. Legacy Driver & Client: Software kernel driver va chuong trinh test IOCTL.
2. Minifilter Driver & Monitor Client: Driver loc he thong tep (File System Minifilter) va chuong trinh lang nghe su kien I/O.

------------------------------------------------------------------------
YEU CAU HE THONG & CHUAN BI
------------------------------------------------------------------------
Do day la driver dung chung chi thu nghiem (Test Certificate), he dieu hanh Windows can duoc bat che do Test Mode:

1. Mo Command Prompt (CMD) bang quyen Administrator.
2. Chay lenh:
      bcdedit /set testsigning on
3. Khoi dong lai may tinh (sau khi khoi dong lai, goc duoi phai man hinh Desktop se hien chu "Test Mode").

4. Cai dat chung chi (Test Certificate) vao may:
   - Chay file install_certificates.bat bang quyen Administrator
   (Hoac nhap dup vao file .cer -> Install Certificate -> Local Machine -> Trusted Root Certification Authorities).

------------------------------------------------------------------------
HUONG DAN SU DUNG: 1. LEGACY DRIVER
------------------------------------------------------------------------
1. Cai dat Service:
   Mo CMD (Admin), chay:
      sc create LegacyDriver binPath= "<duong_dan_toi>\LegacyDriver.sys" type= kernel
   (Hoac nhap chuot phai vao file install_legacy.bat chon Run as administrator).

2. Khoi dong Driver:
      sc start LegacyDriver

3. Chay Client kiem tra:
   Chay file Client.exe bang quyen Administrator de gui cac yeu cau IOCTL.

4. Dung va go bo Driver:
      sc stop LegacyDriver
      sc delete LegacyDriver

------------------------------------------------------------------------
HUONG DAN SU DUNG: 2. MINIFILTER DRIVER
------------------------------------------------------------------------
1. Cai dat Minifilter:
   - Nhap chuot phai vao file MinifilterDriver.inf -> chon "Install".
   (Hoac nhap chuot phai vao install_minifilter.bat chon Run as administrator).

2. Khoi dong Minifilter:
   Mo CMD (Admin), chay:
      fltmc load MinifilterDriver

3. Chay Monitor Client:
   Chay file MonitorClient.exe bang quyen Administrator de theo doi cac hoat dong file system theo thoi gian thuc.

4. Dung Minifilter:
      fltmc unload MinifilterDriver
========================================================================
