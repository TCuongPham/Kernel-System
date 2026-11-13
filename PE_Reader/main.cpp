#include "Pe_Reader.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Pe_Reader.exe <duong_dan_file_pe>\n";
        return 1;
    }

    PeParser parser;
    if (parser.Load(argv[1])) {
        parser.ParseHeaders();
        parser.ParseSections();
        parser.ParseImports();
        parser.ParseExports();
        parser.ParseTLS();
        parser.ParseDotNet();
        parser.ParseDebug();
        parser.ParseSecurity();
    }

    return 0;
}