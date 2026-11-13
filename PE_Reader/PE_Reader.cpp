#include <windows.h>
#include <cstdint>

#include "Pe_Reader.h"

// Hàm tìm section chứa RVA và tính File Offset
uint32_t RvaToOffset(uint32_t rva, PIMAGE_SECTION_HEADER pSections, WORD numSections, size_t fileSize) {
    if (rva == 0) return 0;

    for (WORD i = 0; i < numSections; ++i) {
        DWORD secVA = pSections[i].VirtualAddress;
        DWORD secRaw = pSections[i].PointerToRawData;
        DWORD secRawSize = pSections[i].SizeOfRawData;

        // Chỉ xét dữ liệu có trên đĩa
        if (secRaw != 0 && rva >= secVA && (rva - secVA) < secRawSize) {
            uint64_t fileOffset = static_cast<uint64_t>(rva - secVA) + secRaw;
			// Kiểm tra fileOffset có nằm trong phạm vi file không
            if (fileOffset < fileSize) return static_cast<uint32_t>(fileOffset);
        }
    }
    return 0; // Không tìm thấy section
}

bool PeParser::IsValidOffset(size_t offset, size_t size) const {
    return (offset <= m_fileSize && size <= (m_fileSize - offset));
}

// Hàm đọc chuỗi từ buffer
std::string PeParser::ReadSafeString(size_t offset, size_t maxLen) const {
    if (!IsValidOffset(offset)) return "";
    std::string result;
    for (size_t i = 0; i < maxLen && (offset + i) < m_fileSize; ++i) {
        char c = static_cast<char>(m_buffer[offset + i]);
        if (c == '\0') break;
        result += c;
    }
    return result;
}

// Tính Shannon Entropy: 0.0 -> 8.0 của section
double PeParser::CalculateEntropy(size_t offset, size_t size) const {
    if (size == 0 || offset >= m_fileSize) return 0.0;
    size_t actualSize = (size <= m_fileSize - offset) ? size : (m_fileSize - offset);
    if (actualSize == 0) return 0.0;

    size_t freq[256] = { 0 };
    for (size_t i = 0; i < actualSize; ++i) {
        freq[m_buffer[offset + i]]++;
    }

    double entropy = 0.0;
    double total = static_cast<double>(actualSize);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / total;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

// Chuyển địa chỉ ảo tương đối (RVA) sang địa chỉ thực (Raw) trên đĩa
uint32_t PeParser::RvaToRaw(uint32_t rva) const {
    if (!m_pSectionHeaders || !m_pFileHeader) return 0;
    return RvaToOffset(rva, m_pSectionHeaders, m_pFileHeader->NumberOfSections, m_fileSize);
}

// Hàm nạp và lấy địa chỉ các trường trong cấu trúc PE
bool PeParser::Load(const std::string& filePath) {
	// Mở file PE ở chế độ nhị phân
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Khong the mo file: " << filePath << "\n";
        return false;
    }
	// Đọc nội dung file vào buffer
	std::streamsize fileSize = file.tellg(); // Lấy con trỏ cuối file để xác định kích thước file
    if (fileSize <= 0) {
        std::cerr << "[-] File rong hoac loi doc kich thuoc!\n";
        return false;
    }
    m_fileSize = static_cast<size_t>(fileSize);

	file.seekg(0, std::ios::beg); // Chuyển con trỏ về đầu file
    m_buffer.resize(m_fileSize); // Cấp phát vùng nhớ cho buffer
    file.read(reinterpret_cast<char*>(m_buffer.data()), m_fileSize);

    // Đóng file
    file.close();

    // 1. Check DOS Header
    if (!IsValidOffset(0, sizeof(IMAGE_DOS_HEADER))) return false;

    m_pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer.data());
    if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) { // 'MZ'
        std::cerr << "[-] Khong phai file DOS/PE hop le (Thieu signature MZ)\n";
        return false;
    }

    // 2. Check NT Signature trong NT Header
    if (m_pDosHeader->e_lfanew <= 0 || static_cast<size_t>(m_pDosHeader->e_lfanew) >= m_fileSize) {
        std::cerr << "[-] e_lfanew khong hop le!\n";
        return false;
    }

    DWORD peOffset = m_pDosHeader->e_lfanew;
    if (!IsValidOffset(peOffset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) {
        std::cerr << "[-] e_lfanew tro ra ngoai pham vi file!\n";
        return false;
    }
    DWORD* pNtSignature = reinterpret_cast<DWORD*>(m_buffer.data() + peOffset);
    if (*pNtSignature != IMAGE_NT_SIGNATURE) { // 'PE\0\0'
        std::cerr << "[-] Thieu signature PE hop le!\n";
        return false;
    }

    // 3. File Header
    m_pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(
        m_buffer.data() + peOffset + sizeof(DWORD));

    // 4. Optional Header (Kiem tra 32 hay 64 bit)
    size_t optOffset = static_cast<size_t>(peOffset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!IsValidOffset(optOffset, sizeof(WORD))) {
        std::cerr << "[-] Thieu Optional Header!\n";
        return false;
    }
    uint8_t* pOptStart = m_buffer.data() + optOffset; // Lấy địa chỉ bắt đầu OptHdr

    // Check trường magic
    WORD magic = *reinterpret_cast<WORD*>(pOptStart);
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!IsValidOffset(optOffset, sizeof(IMAGE_OPTIONAL_HEADER32))) return false;
        m_is64Bit = false;
        m_pOptHeader32 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(pOptStart);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (!IsValidOffset(optOffset, sizeof(IMAGE_OPTIONAL_HEADER64))) return false;
        m_is64Bit = true;
        m_pOptHeader64 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(pOptStart);
    }
    else {
        std::cerr << "[-] Magic cua Optional Header khong hop le!\n";
        return false;
    }

    // 5. Section Headers
    if (!IsValidOffset(optOffset, m_pFileHeader->SizeOfOptionalHeader)) {
        std::cerr << "[-] SizeOfOptionalHeader vuot qua kich thuoc file!\n";
        return false;
    }
    uint8_t* pSecStart = pOptStart + m_pFileHeader->SizeOfOptionalHeader;

    if (!IsValidOffset(pSecStart - m_buffer.data(), sizeof(IMAGE_SECTION_HEADER) * static_cast<size_t>(m_pFileHeader->NumberOfSections))) {
        return false;
    }
    m_pSectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(pSecStart);
    return true;
}

