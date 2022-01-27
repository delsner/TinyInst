#include <stdio.h>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>

#include "common.h"

namespace fs = std::filesystem;

struct CoveredAddress {
    std::string test_identifier;
    std::string module_name;
    uint64_t offset;
    std::string filename;
    int line_number;
};

struct CoverageReport {
    // TODO: add proper constructor
    std::vector<CoveredAddress> covered_addresses;
    fs::path output_file;

    void WriteToFile() {
        std::fstream file_stream;
        file_stream.open(output_file, std::fstream::out);
        for (const auto& covered_address : covered_addresses) {
            file_stream << covered_address.test_identifier << ","
                        << covered_address.module_name << ","
                        << "+0x" << std::hex << covered_address.offset << ","
                        << covered_address.filename << ","
                        << covered_address.line_number << "\n";
        }
        file_stream.close();
    }
};

int main(int argc, char** argv)
{
    bool show_help = GetBinaryOption("-help", argc, argv, false);
    if (show_help) {
        printf("Usage:\n");
        printf("%s [options]\n", argv[0]);
        printf("\n");
        printf("Options:\n");
        printf("-ext <root path to search for coverage files>\n");
        printf("\tdefault: .cov\n");
        printf("-root <root path to search for coverage files>\n");
        printf("\tdefault: current working directory\n");
        printf("-symbol_path <symbol path for covered module>\n");
        printf("-output <output CSV filename>\n");
        printf("\tdefault: coverage.csv\n");
        printf("\n");
        printf("Help:\n");
        printf("-help Shows this information.\n");
        return 0;
    }

    char *root_arg = GetOption("-root", argc, argv);
    std::string root;
    if (root_arg)
        root = std::string(root_arg);
    else
        root = std::string(".");

    char *ext_arg = GetOption("-ext", argc, argv);
    std::string ext;
    if (ext_arg)
        ext = std::string(ext_arg);
    else
        ext = std::string(".cov");

    char* output_arg = GetOption("-output", argc, argv);
    fs::path output_file;
    if (output_arg)
        output_file = fs::path(output_arg);
    else
        output_file = fs::path("coverage.csv");

    std::list <char*> module_symbol_paths;
    GetOptionAll("-symbol_path", argc, argv, &module_symbol_paths);

    // Collect all coverage files in directory with coverage extension.
    CoverageReport coverageReport;
    coverageReport.output_file = output_file;
    for (const auto& path : fs::directory_iterator(root)) {
        if (path.path().extension() == ext) {
            std::ifstream is(path.path());
            std::string line;
            while (std::getline(is, line))
            {
                // Lookup symbol and store (test_id, module_name, offset, file, line) into coverage report
                std::size_t module_name_len = line.find("+");
                if (module_name_len != std::string::npos) {
                    CoveredAddress covered_address;
                    covered_address.test_identifier = path.path().stem().string();
                    covered_address.module_name = line.substr(0, module_name_len);
                    covered_address.offset = std::strtoul(line.substr(module_name_len, line.size()).c_str(), nullptr, 16);
                    covered_address.filename = "file";
                    covered_address.line_number = 0;
                    coverageReport.covered_addresses.push_back(covered_address);
                }
            }
        }
    }
    coverageReport.WriteToFile();

    return 0;
}