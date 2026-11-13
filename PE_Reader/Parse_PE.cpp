#include <windows.h>
#include <cstdint>

#include "Pe_Reader.h"

// File & Opt Header 
void PeParser::ParseHeaders() {
    std::cout << "\n================= [FILE HEADER] =================\n";
    std::cout << "Machine:   0x" << std::hex << m_pFileHeader->Machine;
    if (m_pFileHeader->Machine == IMAGE_FILE_MACHINE_I386)  std::cout << " (x86)\n";
    else if (m_pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) std::cout << " (x64 / AMD64)\n";
    else std::cout << " (Another)\n";

    std::cout << "Sections Count:     " << std::dec << m_pFileHeader->NumberOfSections << "\n";
    std::cout << "Time Date Stamp:   0x" << std::hex << m_pFileHeader->TimeDateStamp << "\n";
    
    std::cout << "\n=============== [OPTIONAL HEADER] ===============\n";
    uint64_t imageBase = m_is64Bit ? m_pOptHeader64->ImageBase : m_pOptHeader32->ImageBase;
    uint32_t entryPoint = m_is64Bit ? m_pOptHeader64->AddressOfEntryPoint : m_pOptHeader32->AddressOfEntryPoint;
    uint32_t secAlign = m_is64Bit ? m_pOptHeader64->SectionAlignment : m_pOptHeader32->SectionAlignment;
    uint32_t fileAlign = m_is64Bit ? m_pOptHeader64->FileAlignment : m_pOptHeader32->FileAlignment;

    std::cout << "PE:                   " << (m_is64Bit ? "PE32+ (64-bit)" : "PE32 (32-bit)") << "\n";
	std::cout << "ImageBase:             0x" << std::hex << imageBase << "\n";  // Địa chỉ cơ sở (ImageBase) của file PE khi load vào bộ nhớ
	std::cout << "AddressOfEntryPoint:   0x" << std::hex << entryPoint << " (RVA)\n"; // RVA (Relative Virtual Address) của Entry Point
	std::cout << "Section / File Align:  0x" << secAlign << " / 0x" << fileAlign << std::dec << "\n"; // SectionAlignment và FileAlignment 

    WORD subsystem = m_is64Bit ? m_pOptHeader64->Subsystem : m_pOptHeader32->Subsystem;
    WORD dllChar   = m_is64Bit ? m_pOptHeader64->DllCharacteristics : m_pOptHeader32->DllCharacteristics;
    bool isDll     = (m_pFileHeader->Characteristics & IMAGE_FILE_DLL) != 0;

    std::cout << "File Type:             " << (isDll ? "DLL" : "EXE") << "\n";
    std::cout << "Subsystem:             " << subsystem;
    if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) std::cout << " (Windows GUI)\n";
    else if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) std::cout << " (Console CUI)\n";
    else if (subsystem == IMAGE_SUBSYSTEM_NATIVE) std::cout << " (Native / Driver)\n";
    else std::cout << "\n";

    std::cout << "Mitigations:           "
		<< ((dllChar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) ? "[ASLR] " : "") // Áp dụng ASLR (Address Space Layout Randomization)
		<< ((dllChar & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ? "[DEP/NX] " : "")  // Áp dụng DEP/NX (Data Execution Prevention / No eXecute)
		<< ((dllChar & IMAGE_DLLCHARACTERISTICS_GUARD_CF) ? "[CFG] " : "") // Áp dụng Control Flow Guard (CFG)
		<< ((dllChar & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) ? "[HighEntropyVA]" : "") // Áp dụng High Entropy VA (chỉ có trên PE32+)
        << "\n";
}

// Section Header
void PeParser::ParseSections() {
    std::cout << "\n================== [SECTION HEADERS] ==================\n";
    std::cout << std::left
        << std::setw(10) << "Name"
        << std::setw(12) << "VirtSize"
        << std::setw(12) << "VirtAddr"
        << std::setw(12) << "RawSize"
        << std::setw(12) << "RawOffset"
        << std::setw(16) << "Characteristics"
        << "Entropy\n";

    for (WORD i = 0; i < m_pFileHeader->NumberOfSections; ++i) {
        char name[9] = { 0 };
        memcpy(name, m_pSectionHeaders[i].Name, 8);

        double entropy = 0.0;
        if (m_pSectionHeaders[i].PointerToRawData != 0 && m_pSectionHeaders[i].SizeOfRawData != 0) {
            entropy = CalculateEntropy(m_pSectionHeaders[i].PointerToRawData, m_pSectionHeaders[i].SizeOfRawData);
        }

        std::cout << std::left
            << std::setw(10) << name
            << "0x" << std::setw(10) << std::hex << m_pSectionHeaders[i].Misc.VirtualSize
            << "0x" << std::setw(10) << m_pSectionHeaders[i].VirtualAddress
            << "0x" << std::setw(10) << m_pSectionHeaders[i].SizeOfRawData
            << "0x" << std::setw(10) << m_pSectionHeaders[i].PointerToRawData
            << "0x" << std::setw(14) << m_pSectionHeaders[i].Characteristics
            << std::dec << std::fixed << std::setprecision(2) << std::setw(8) << entropy
            << std::defaultfloat << std::setprecision(6);

        if ((m_pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (m_pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
            std::cout << "W+X ";
        }
        if (entropy >= 7.0) {
            std::cout << "High Entropy (Packed/Encrypted)";
        }
        std::cout << "\n";
    }
}

// Import Directory (IAT table)
void PeParser::ParseImports() {
    std::cout << "\n=============== [IMPORT DIRECTORY (IAT)] ===============\n";

    // Kiểm tra loại PE và tìm mảng IMPORT_DESCRIPTOR
	DWORD numRva = m_is64Bit ? m_pOptHeader64->NumberOfRvaAndSizes : m_pOptHeader32->NumberOfRvaAndSizes; // Lấy số lượng mảng DataDirectory
    if (numRva <= IMAGE_DIRECTORY_ENTRY_IMPORT) {
        std::cout << "File khong co Import Directory.\n";
        return;
    }

    IMAGE_DATA_DIRECTORY importDir = m_is64Bit
        ? m_pOptHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        : m_pOptHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress == 0) {
        std::cout << "File khong co Import Directory.\n";
        return;
    }

    // Chuyển RVA sang địa chỉ Offset trên đĩa
    uint32_t importRaw = RvaToRaw(importDir.VirtualAddress);
    if (importRaw == 0 || !IsValidOffset(importRaw, sizeof(IMAGE_IMPORT_DESCRIPTOR))) return;

    // Lấy con trỏ đến địa chỉ IMPORT_DESCRIPTOR
    auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(m_buffer.data() + importRaw);

    // Lap qua tung DLL Descriptor (ket thuc bang mot struct toan byte 0)
    while (IsValidOffset(reinterpret_cast<const uint8_t*>(pImportDesc) - m_buffer.data(), sizeof(IMAGE_IMPORT_DESCRIPTOR))
        && pImportDesc->Name != 0) {
        // Lấy offset trường Name trong PIMAGE_IMPORT_DESCRIPTOR
        uint32_t nameRaw = RvaToRaw(pImportDesc->Name);

        if (nameRaw != 0 && IsValidOffset(nameRaw)) {
            // Lấy tên thư viện DLL
            std::cout << "\n[+] DLL: " << ReadSafeString(nameRaw) << "\n";
        }

        // Uu tien doc OriginalFirstThunk (ILT)
        uint32_t thunkRVA = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;

        uint32_t thunkRaw = RvaToRaw(thunkRVA); // Lấy offset của thunk
        if (thunkRaw != 0) {
            if (m_is64Bit) {
				// Lấy con trỏ trỏ đến mảng IMAGE_THUNK_DATA64
                auto pThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(m_buffer.data() + thunkRaw);

				// Lap qua tung API trong DLL (ket thuc bang mot struct toan byte 0)
                while (IsValidOffset(reinterpret_cast<const uint8_t*>(pThunk) - m_buffer.data(), sizeof(IMAGE_THUNK_DATA64))
                    && pThunk->u1.AddressOfData != 0) {
					// Kiểm tra xem là import theo Ordinal hay Name ở bit 63
                    if (IMAGE_SNAP_BY_ORDINAL64(pThunk->u1.Ordinal)) {
                        std::cout << "    Ordinal: " << std::dec << IMAGE_ORDINAL64(pThunk->u1.Ordinal) << "\n";
                    }
                    else // Import theo tên
                    {
						// Lấy offset của IMAGE_IMPORT_BY_NAME từ AddressOfData
                        if (pThunk->u1.AddressOfData <= UINT32_MAX) {
                            uint32_t dataRaw = RvaToRaw(static_cast<uint32_t>(pThunk->u1.AddressOfData));
                            if (dataRaw != 0 && IsValidOffset(dataRaw, sizeof(IMAGE_IMPORT_BY_NAME))) {
								std::cout << "    API: " << ReadSafeString(dataRaw + offsetof(IMAGE_IMPORT_BY_NAME, Name)) << "\n"; // Bỏ qua trường Hint (2 byte) để lấy tên hàm
                            }
                        }
                    }
                    pThunk++;
                }
            }
            else { // 32-bit
                auto pThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(m_buffer.data() + thunkRaw);
                while (IsValidOffset(reinterpret_cast<const uint8_t*>(pThunk) - m_buffer.data(), sizeof(IMAGE_THUNK_DATA32))
                    && pThunk->u1.AddressOfData != 0) {
                    if (IMAGE_SNAP_BY_ORDINAL32(pThunk->u1.Ordinal)) {
                        std::cout << "    Ordinal: " << std::dec << IMAGE_ORDINAL32(pThunk->u1.Ordinal) << "\n";
                    }
                    else {
                        uint32_t dataRaw = RvaToRaw(pThunk->u1.AddressOfData);
                        if (dataRaw != 0 && IsValidOffset(dataRaw, sizeof(IMAGE_IMPORT_BY_NAME))) {
                            std::cout << "    API: " << ReadSafeString(dataRaw + offsetof(IMAGE_IMPORT_BY_NAME, Name)) << "\n";
                        }
                    }
                    pThunk++;
                }
            }
        }
        pImportDesc++;
    }
}

// Export Directory
void PeParser::ParseExports() {
    std::cout << "\n================== [EXPORT DIRECTORY] ==================\n";

	// Kiểm tra loại PE và tìm mảng EXPORT_DIRECTORY
    DWORD numRva = m_is64Bit ? m_pOptHeader64->NumberOfRvaAndSizes : m_pOptHeader32->NumberOfRvaAndSizes;
    if (numRva <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        std::cout << "File khong co Export Directory.\n";
        return;
    }

    IMAGE_DATA_DIRECTORY exportDir = m_is64Bit
        ? m_pOptHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        : m_pOptHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDir.VirtualAddress == 0) {
        std::cout << "File khong co Export Directory.\n";
        return;
    }

	// Chuyển RVA của EXPORT_DIRECTORY sang địa chỉ Offset
    uint32_t exportRaw = RvaToRaw(exportDir.VirtualAddress);
    if (exportRaw == 0 || !IsValidOffset(exportRaw, sizeof(IMAGE_EXPORT_DIRECTORY))) return;

	// Lấy con trỏ đến địa chỉ EXPORT_DIRECTORY
    auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(m_buffer.data() + exportRaw);

	// Lấy tên module (DLL) từ trường Name
    uint32_t nameRaw = RvaToRaw(pExport->Name);
    if (nameRaw != 0 && IsValidOffset(nameRaw)) {
        std::cout << "Module Name: " << ReadSafeString(nameRaw) << "\n";
    }

	// In số lượng hàm và tên
    std::cout << "- Number of Functions: " << std::dec << pExport->NumberOfFunctions << "\n";
    std::cout << "- Number of Names:     " << pExport->NumberOfNames << "\n";

    if (pExport->NumberOfNames == 0 || pExport->NumberOfFunctions == 0) return;

	// Lấy con trỏ trỏ đến mảng AddressOfFunctions (Bảng địa chỉ hàm), AddressOfNames (Bảng tên hàm), AddressOfNameOrdinals (Bảng chỉ số thứ tự liên kết Name và địa chỉ)
    uint32_t funcsRaw = RvaToRaw(pExport->AddressOfFunctions);
    uint32_t namesRaw = RvaToRaw(pExport->AddressOfNames);
    uint32_t ordsRaw  = RvaToRaw(pExport->AddressOfNameOrdinals);
	// Kiểm tra tính hợp lệ của các mảng
    if (funcsRaw == 0 || !IsValidOffset(funcsRaw, static_cast<size_t>(pExport->NumberOfFunctions) * sizeof(uint32_t)) ||
        namesRaw == 0 || !IsValidOffset(namesRaw, static_cast<size_t>(pExport->NumberOfNames) * sizeof(uint32_t)) ||
        ordsRaw  == 0 || !IsValidOffset(ordsRaw,  static_cast<size_t>(pExport->NumberOfNames) * sizeof(uint16_t))) {
        std::cerr << "[-] Bang Export bi hong hoac vuot qua pham vi file!\n";
        return;
    }

    uint32_t* pFunctions = reinterpret_cast<uint32_t*>(m_buffer.data() + funcsRaw);
    uint32_t* pNames = reinterpret_cast<uint32_t*>(m_buffer.data() + namesRaw);
    uint16_t* pOrdinals = reinterpret_cast<uint16_t*>(m_buffer.data() + ordsRaw);

	// In ra danh sách các hàm Exported
    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
		uint32_t fnNameRaw = RvaToRaw(pNames[i]);  // Lấy offset của tên hàm từ mảng AddressOfNames
        std::string fnName = (fnNameRaw != 0 && IsValidOffset(fnNameRaw)) ? ReadSafeString(fnNameRaw) : "<Corrupted>";

		// Lấy chỉ số thứ tự (Ordinal), sau đó dùng chỉ số này lấy RVA của hàm từ AddressOfFunctions
        uint16_t ordinal = pOrdinals[i];
        if (ordinal >= pExport->NumberOfFunctions) {
            std::cout << "    [Invalid Ordinal: " << std::dec << ordinal << "] " << fnName << "\n";
            continue;
        }
        uint32_t fnRva = pFunctions[ordinal];

        // Kiểm tra xem fnRva có nằm vào vùng của Export Directory 
        if (fnRva >= exportDir.VirtualAddress && (fnRva - exportDir.VirtualAddress) < exportDir.Size) {
            uint32_t fwdRaw = RvaToRaw(fnRva);
            std::string fwdName = (fwdRaw != 0 && IsValidOffset(fwdRaw)) ? ReadSafeString(fwdRaw) : "<Invalid>";

            std::cout << "    [" << std::dec << std::setw(4) << (ordinal + pExport->Base) << "] "
                << fnName << "  --->  [Forwarded to: " << fwdName << "]\n";
        }
        else {
            // Hàm bình thường trỏ tới code
            std::cout << "    [" << std::dec << std::setw(4) << (ordinal + pExport->Base) << "] "
                << "RVA: 0x" << std::hex << std::setw(8) << fnRva << std::dec << "  "
                << fnName << "\n";
        }
    }
}

// TLS Directory
void PeParser::ParseTLS() {
    std::cout << "\n================== [TLS DIRECTORY] ==================\n";

	// Kiểm tra loại PE và tìm mảng TLS_DIRECTORY
    DWORD numRva = m_is64Bit ? m_pOptHeader64->NumberOfRvaAndSizes : m_pOptHeader32->NumberOfRvaAndSizes;
    if (numRva <= IMAGE_DIRECTORY_ENTRY_TLS) {
        std::cout << "File khong su dung TLS Directory.\n";
        return;
    }

    IMAGE_DATA_DIRECTORY tlsDir = m_is64Bit
        ? m_pOptHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
        : m_pOptHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.VirtualAddress == 0) {
        std::cout << "File khong su dung TLS Directory.\n";
        return;
    }
	// Chuyển RVA sang địa chỉ Offset trên đĩa
    uint32_t tlsRaw = RvaToRaw(tlsDir.VirtualAddress);

    if (m_is64Bit) {
        if (tlsRaw == 0 || !IsValidOffset(tlsRaw, sizeof(IMAGE_TLS_DIRECTORY64))) return;

		// Lấy con trỏ trỏ đến IMAGE_TLS_DIRECTORY64
        auto pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(m_buffer.data() + tlsRaw);

        // AddressOfCallBacks trong TLS_DIRECTORY64 la VA (Virtual Address), can tru ImageBase de ra RVA
        uint64_t imageBase = m_pOptHeader64->ImageBase;
        if (pTLS->AddressOfCallBacks >= imageBase && (pTLS->AddressOfCallBacks - imageBase) <= UINT32_MAX) {
            uint32_t callbackArrayRva = static_cast<uint32_t>(pTLS->AddressOfCallBacks - imageBase);
			uint32_t callbackRaw = RvaToRaw(callbackArrayRva); // Lấy offset của mảng AddressOfCallBacks

            if (callbackRaw != 0) {
				// Lấy con trỏ trỏ đến mảng AddressOfCallBacks
                auto pCallback = reinterpret_cast<uint64_t*>(m_buffer.data() + callbackRaw);
                int idx = 0;
                while (IsValidOffset(reinterpret_cast<const uint8_t*>(pCallback) - m_buffer.data(), sizeof(uint64_t)) && *pCallback != 0) {
                    std::cout << "    [!] TLS Callback " << std::dec << idx++ << ": 0x" << std::hex << *pCallback << std::dec << "\n";
                    pCallback++;
                }
            }
        }
    }
    else { // 32-bit
        if (tlsRaw == 0 || !IsValidOffset(tlsRaw, sizeof(IMAGE_TLS_DIRECTORY32))) return;
        auto pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(m_buffer.data() + tlsRaw);
        uint32_t imageBase = m_pOptHeader32->ImageBase;
        if (pTLS->AddressOfCallBacks >= imageBase) {
            uint32_t callbackArrayRva = pTLS->AddressOfCallBacks - imageBase;
            uint32_t callbackRaw = RvaToRaw(callbackArrayRva);
            if (callbackRaw != 0) {
                auto pCallback = reinterpret_cast<uint32_t*>(m_buffer.data() + callbackRaw);
                int idx = 0;
                while (IsValidOffset(reinterpret_cast<const uint8_t*>(pCallback) - m_buffer.data(), sizeof(uint32_t))
                    && *pCallback != 0) {
                    std::cout << "    [!] TLS Callback " << std::dec << idx++ << ": 0x" << std::hex << *pCallback << std::dec << "\n";
                    pCallback++;
                }
            }
        }
    }
}

// Nhận diện file .NET (CLR / COM Descriptor Directory)
void PeParser::ParseDotNet() {
    std::cout << "\n================ [.NET / CLR INFO] ================\n";

    DWORD numRva = m_is64Bit ? m_pOptHeader64->NumberOfRvaAndSizes : m_pOptHeader32->NumberOfRvaAndSizes;

	// Kiểm tra có tồn tại IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 
    if (numRva <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
        std::cout << "File khong phai .NET (Native PE).\n";
        return;
    }
	// Lấy RVA của COM_DESCRIPTOR
    IMAGE_DATA_DIRECTORY comDir = m_is64Bit
        ? m_pOptHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        : m_pOptHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

	// Kiểm tra COM_DESCRIPTOR có hợp lệ
    if (comDir.VirtualAddress == 0 || comDir.Size == 0) {
        std::cout << "File khong phai .NET (Native PE).\n";
        return;
    }

	// Chuyển RVA sang địa chỉ Offset trên đĩa
    uint32_t corRaw = RvaToRaw(comDir.VirtualAddress);
	// Kiểm tra tính hợp lệ của CLR Header
    if (corRaw == 0 || !IsValidOffset(corRaw, sizeof(IMAGE_COR20_HEADER))) {
        std::cout << "Phat hien .NET Descriptor nhung CLR Header bi hong!\n";
        return;
    }

	// Lấy con trỏ trỏ đến IMAGE_COR20_HEADER
    auto pCor = reinterpret_cast<PIMAGE_COR20_HEADER>(m_buffer.data() + corRaw);
    std::cout << "[+] File .NET\n";
    std::cout << "    CLR Runtime Version: " << std::dec << pCor->MajorRuntimeVersion << "." << pCor->MinorRuntimeVersion << "\n";
    std::cout << "    EntryPoint Token:    0x" << std::hex << pCor->EntryPointToken << std::dec << "\n";
    std::cout << "    Flags:               0x" << std::hex << pCor->Flags << std::dec << " ";
	if (pCor->Flags & COMIMAGE_FLAGS_ILONLY) std::cout << "[IL_ONLY] "; // Chỉ chứa IL, không có mã gốc (Native Code)
	if (pCor->Flags & COMIMAGE_FLAGS_32BITREQUIRED) std::cout << "[32BIT_REQ] ";   // Chỉ chạy trên nền tảng 32-bit
	if (pCor->Flags & COMIMAGE_FLAGS_STRONGNAMESIGNED) std::cout << "[STRONG_NAME]"; // Có chữ ký số (Strong Name) để xác thực toàn vẹn Assembly
    std::cout << "\n";
}

// Đọc Debug Directory để lấy đường dẫn PDB
void PeParser::ParseDebug() {
    std::cout << "\n============== [DEBUG / PDB INFO] =============\n";

	// Kiểm tra loại PE và tìm mảng DEBUG_DIRECTORY
    DWORD numRva = m_is64Bit ? m_pOptHeader64->NumberOfRvaAndSizes : m_pOptHeader32->NumberOfRvaAndSizes;
    if (numRva <= IMAGE_DIRECTORY_ENTRY_DEBUG) {
        std::cout << "File khong co Debug Directory.\n";
        return;
    }

    IMAGE_DATA_DIRECTORY debugDir = m_is64Bit
        ? m_pOptHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
        : m_pOptHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    if (debugDir.VirtualAddress == 0 || debugDir.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) {
        std::cout << "File khong co Debug Directory.\n";
        return;
    }

	// Chuyển RVA sang địa chỉ Offset trên đĩa
    uint32_t debugRaw = RvaToRaw(debugDir.VirtualAddress);
    if (debugRaw == 0 || !IsValidOffset(debugRaw, sizeof(IMAGE_DEBUG_DIRECTORY))) return;

    // Tính số phần tử IMAGE_DEBUG_DIRECTORY trong mảng
    size_t entryCount = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);

	// Lấy con trỏ trỏ đến mảng
    auto pDebug = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(m_buffer.data() + debugRaw);
    bool foundPdb = false;

    for (size_t i = 0; i < entryCount; ++i) {
        if (!IsValidOffset(static_cast<size_t>(debugRaw) + i * sizeof(IMAGE_DEBUG_DIRECTORY), sizeof(IMAGE_DEBUG_DIRECTORY))) {
            break;
        }
		// Chỉ xét loại Debug Directory là CodeView (chứa thông tin PDB)
        if (pDebug[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
			uint32_t cvRaw = pDebug[i].PointerToRawData; // Lấy offset của CodeView Debug Info từ PointerToRawData

            // Nếu PointerToRawData = 0, lấy từ AddressOfRawData (RVA) và chuyển sang Raw Offset
            if (cvRaw == 0 && pDebug[i].AddressOfRawData != 0) {
                cvRaw = RvaToRaw(pDebug[i].AddressOfRawData);
            }

            if (cvRaw != 0 && IsValidOffset(cvRaw, sizeof(DWORD))) {
				// Kiểm tra chữ ký "RSDS" hoặc "NB10" trong CodeView Debug Info
                DWORD cvSig = *reinterpret_cast<const DWORD*>(m_buffer.data() + cvRaw);

                if (cvSig == 0x53445352 && IsValidOffset(cvRaw, 24)) { // "RSDS"
                    uint32_t age = *reinterpret_cast<const uint32_t*>(m_buffer.data() + cvRaw + 20);
                    std::cout << "[+] PDB Path (RSDS): " << ReadSafeString(cvRaw + 24, 512)
                              << " (Age: " << std::dec << age << ")\n";
                    foundPdb = true;
                }
                else if (cvSig == 0x3031424E && IsValidOffset(cvRaw, 16)) { // "NB10"
                    std::cout << "[+] PDB Path (NB10): " << ReadSafeString(cvRaw + 16, 512) << "\n";
                    foundPdb = true;
                }
            }
        }
    }

    if (!foundPdb) {
        std::cout << "Co Debug Directory nhung khong chua duong dan PDB.\n";
    }
}

// Kiểm tra Chữ ký số (Security Directory) 
void PeParser::ParseSecurity() {
    std::cout << "\n============== [SECURITY] =================\n";

    // VirtualAddress trong Security la RAW Offset)
    DWORD numRva = m_is64Bit ? m_pOptHeader64->NumberOfRvaAndSizes : m_pOptHeader32->NumberOfRvaAndSizes;

	// Kiểm tra xem có tồn tại Security Directory và lấy địa chỉ tới IMAGE_DIRECTORY_ENTRY_SECURITY
	IMAGE_DATA_DIRECTORY secDir = { 0, 0 };     // Khởi tạo
    if (numRva > IMAGE_DIRECTORY_ENTRY_SECURITY) {
        secDir = m_is64Bit
            ? m_pOptHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]
            : m_pOptHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
	// Kiểm tra Security Directory hợp lệ
    bool hasSignature = (secDir.VirtualAddress != 0 && secDir.Size != 0 &&
                         IsValidOffset(secDir.VirtualAddress, secDir.Size));
    if (hasSignature) {
        std::cout << "Chu ky so (Authenticode): (Offset: 0x" << std::hex << secDir.VirtualAddress
                  << std::dec << ", Size: " << secDir.Size << " bytes)\n";
    }
    else {
        std::cout << "Chu ky so (Authenticode): (Offset: 0" << ", Size: 0" << " bytes)\n";
    }
}