#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <cmath>

class PeParser {
private:
    std::vector<uint8_t> m_buffer;
    size_t m_fileSize = 0;
    PIMAGE_DOS_HEADER       m_pDosHeader = nullptr;
    PIMAGE_FILE_HEADER      m_pFileHeader = nullptr;
    PIMAGE_SECTION_HEADER   m_pSectionHeaders = nullptr;

    bool m_is64Bit = false;
    PIMAGE_OPTIONAL_HEADER32 m_pOptHeader32 = nullptr;
    PIMAGE_OPTIONAL_HEADER64 m_pOptHeader64 = nullptr;
    
	// Chuyển địa chỉ ảo tương đối (RVA) sang địa chỉ thực (Raw) trên đĩa 
    uint32_t RvaToRaw(uint32_t rva) const;

    bool IsValidOffset(size_t offset, size_t size = 1) const;
    std::string ReadSafeString(size_t offset, size_t maxLen = 256) const;
    double CalculateEntropy(size_t offset, size_t size) const;

public:
    bool Load(const std::string& filePath);
    void ParseHeaders();
    void ParseSections();
    void ParseImports();
    void ParseExports();
    void ParseTLS();
    void ParseDotNet();
    void ParseDebug();
    void ParseSecurity();
};