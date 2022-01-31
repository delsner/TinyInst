#include <stdio.h>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>

#include "common.h"
#include "dbghelp.h"

namespace fs = std::filesystem;

struct CoveredAddress {
	std::string module_name;
	uint64_t offset;
	std::string filename;
	int line_number;

	inline bool operator==(const CoveredAddress& rhs) const {
		return (filename + std::to_string(line_number)).compare(rhs.filename + std::to_string(rhs.line_number)) == 0;
	}
};

struct TestCoverage {
	std::string test_identifier;
	std::vector<CoveredAddress> covered_addresses;

	bool Contains(const CoveredAddress &covered_address) {
		std::vector<CoveredAddress>::iterator it;
		it = std::find(covered_addresses.begin(), covered_addresses.end(), covered_address);
		return it != covered_addresses.end();
	}
};

struct CoverageReport {
	std::vector<TestCoverage> covered_tests;
	fs::path output_file;

	struct CoveredSourceFileLCOV {
		int LF = 0; // number of instrumented lines
		int LH = 0; // number of lines with non-zero execution count
		std::string filename;
		std::map<int, int> line_number_hit_count; // <line_number, hits>
	};

	void SaveAsCSV() {
		std::fstream file_stream;
		file_stream.open(output_file, std::fstream::out);
		for (const auto& covered_test : covered_tests) {
			for (const auto& covered_address : covered_test.covered_addresses) {
				file_stream << covered_test.test_identifier << ","
					<< covered_address.module_name << ","
					<< "+0x" << std::hex << covered_address.offset << ","
					<< covered_address.filename << ","
					<< std::dec << covered_address.line_number << "\n";
			}
		}
		file_stream.close();
	}

	// Simple approach that currently doesn't care about LF/LH.
	void SaveAsLCOV() {
		for (const auto& covered_test : covered_tests) {
			std::fstream file_stream;
			file_stream.open(covered_test.test_identifier + ".info", std::fstream::out);
			file_stream << "TN:" << covered_test.test_identifier << "\n";
			std::map<std::string, CoveredSourceFileLCOV> covered_source_files;
			for (const auto& covered_address : covered_test.covered_addresses) {
				if (!covered_source_files.count(covered_address.filename)) {
					CoveredSourceFileLCOV covered_source_file;
					covered_source_file.filename = covered_address.filename;
					covered_source_file.line_number_hit_count[covered_address.line_number] = 1;
					covered_source_file.LF++;
					covered_source_file.LH++;
					covered_source_files[covered_address.filename] = covered_source_file;
				}
				else {
					covered_source_files[covered_address.filename].line_number_hit_count[covered_address.line_number] = 1;
					covered_source_files[covered_address.filename].LF++;
					covered_source_files[covered_address.filename].LH++;
				}
			}
			for (const auto& covered_source_file : covered_source_files) {
				file_stream << "SF:" << covered_source_file.second.filename << "\n";
				for (const auto covered_line : covered_source_file.second.line_number_hit_count) {
					file_stream << "DA:" << covered_line.first << "," << covered_line.second << "\n";
				}
				file_stream << "LF:" << covered_source_file.second.LF << "\n";
				file_stream << "LH:" << covered_source_file.second.LH << "\n";
				file_stream << "end_of_record\n";
			}
			file_stream.close();
		}
	}
};

// Main routine.
int main(int argc, char** argv)
{
	bool drop_duplicate_lines = GetBinaryOption("-drop_duplicate_lines", argc, argv, true);
	std::string ext = std::string(GetOptionOrDefault("-ext", argc, argv, ".cov"));
	std::regex regex = std::regex(GetOptionOrDefault("-regex", argc, argv, ".*"));
	std::string root = std::string(GetOptionOrDefault("-root", argc, argv, "."));
	fs::path output_file = fs::path(GetOptionOrDefault("-output", argc, argv, "coverage.csv"));
	bool trace_debug = GetBinaryOption("-trace_debug", argc, argv, false);

	std::list <char*> module_symbol_paths;
	GetOptionAll("-symbol_path", argc, argv, &module_symbol_paths);

	if (argc < 2 || module_symbol_paths.size() == 0) {
		printf("Usage:\n");
		printf("%s [options]\n", argv[0]);
		printf("\n");
		printf("Options:\n");
		printf("-drop_duplicate_lines\n");
		printf("\tdefault: false\n");
		printf("-ext <file extension for coverage files>\n");
		printf("\tdefault: .cov\n");
		printf("-regex <regex for included files>\n");
		printf("\tdefault: .*\n");
		printf("-root <root path to search for coverage files>\n");
		printf("\tdefault: current working directory\n");
		printf("-symbol_path <symbol path for covered module>\n");
		printf("\trequired: provide at least one symbol path (searched recursively)\n");
		printf("-output <output filename>\n");
		printf("\tdefault: coverage.csv\n");
		return 0;
	}

	// Join symbol paths to user symbol search path.
	std::string symbol_search_path;
	for (const auto& path : module_symbol_paths) {
		symbol_search_path += path;
		symbol_search_path += ';';
	}
	// Add some default paths.
	symbol_search_path += ".;";
	symbol_search_path += "SRV*c:\\symbolcache*https://msdl.microsoft.com/download/symbols";

	// Collect all coverage files in directory with coverage extension.
	CoverageReport coverage_report;
	coverage_report.output_file = output_file;
	HANDLE current_proc_handle = GetCurrentProcess();
	printf("DEBUG: Using current process handle %d\n", current_proc_handle);
	bool symbol_handler_initialized = false;
	std::map<std::string, uint64_t> loaded_modules;
	for (const auto& path : fs::directory_iterator(root)) {
		if (path.path().extension() == ext) {
			std::ifstream is(path.path());
			std::string line;
			TestCoverage test_coverage;
			test_coverage.test_identifier = path.path().stem().string();
			while (std::getline(is, line))
			{
				// Look up symbol and store (test_id, module_name, offset, file, line) into coverage report
				std::size_t module_name_len = line.find("+");
				if (module_name_len != std::string::npos) {
					CoveredAddress covered_address;
					covered_address.module_name = line.substr(0, module_name_len);
					covered_address.offset = std::strtoul(line.substr(module_name_len, line.size()).c_str(), nullptr, 16);
					// Init symbol handler.
					DWORD error;
					if (!symbol_handler_initialized && current_proc_handle) {
						SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
						printf("DEBUG: Initializing symbol handler with search path: %s\n", symbol_search_path.c_str());
						if (!SymInitialize(
							current_proc_handle,                // Current process handle, although this simply has to be a UID.
							symbol_search_path.c_str(),         // User search path for symbols, semicolon-separated list of symbol modules (search for symbol files is done recursively).
							FALSE)) {                           // fInvadeProcess is set to false, to skip loading symbols for already loaded modules.
							error = GetLastError();
							printf("ERROR: SymInitialize returned error: %d\n", error);
							SymCleanup(current_proc_handle);
							return 1;
						}
						symbol_handler_initialized = true;
					}
					// Load module if not yet loaded.
					const char* module_name = covered_address.module_name.c_str();
					if (loaded_modules.count(module_name)) {
						printf("DEBUG: Using already loaded module: %s\n", module_name);
					}
					else {
						printf("DEBUG: Starting to load module: %s\n", module_name);
						DWORD64 dwBaseAddr = 0;
						DWORD64 dwDllBase = SymLoadModuleEx(
							current_proc_handle,                    // target process 
							NULL,                                   // handle to image - not used
							module_name,                            // name of image file (can be a name that is resolved through the symbol handler path)
							NULL,                                   // name of module - not required
							dwBaseAddr,                             // base address - not required (set to 0 here)
							0,                                      // size of image - not required
							NULL,                                   // MODLOAD_DATA used for special cases 
							0);
						if (!dwDllBase) {
							error = GetLastError();
							if (error != ERROR_SUCCESS) {
								printf("ERROR: SymLoadModuleEx returned error: %d\n", error);
								continue;
							}
						}
						else {
							printf("DEBUG: Successfully loaded module (base address): %s (0x%llx)\n", module_name, dwDllBase);
							loaded_modules[module_name] = dwDllBase;
						}
					}
					DWORD dwDisplacement;
					IMAGEHLP_LINE64 symbol_line;
					memset(&symbol_line, 0x0, sizeof(symbol_line));
					symbol_line.SizeOfStruct = sizeof(symbol_line);
					printf("DEBUG: Starting to load symbol info for line: %s\n", line.c_str());
					if (trace_debug)
						printf("TRACE: SymGetLineFromAddr64(0x%llx + 0x%llx)\n", loaded_modules[module_name], covered_address.offset);
					if (SymGetLineFromAddr64(current_proc_handle, loaded_modules[module_name] + covered_address.offset, &dwDisplacement, &symbol_line)) {
						if (trace_debug)
							printf("TRACE: Found filename (%s) and line (%d)\n", symbol_line.FileName, symbol_line.LineNumber);
						covered_address.filename = symbol_line.FileName;
						covered_address.line_number = symbol_line.LineNumber;
						// We only add a covered address if it matches the regex and has not yet been added (in case duplicates are dropped).
						if (std::regex_match(covered_address.filename, regex) && (!drop_duplicate_lines || !test_coverage.Contains(covered_address))) {
							printf("DEBUG: Adding filename (%s) due to regex match.\n", covered_address.filename.c_str());
							test_coverage.covered_addresses.push_back(covered_address);
						}
					}
					else {
						error = GetLastError();
						if (error != ERROR_SUCCESS) {
							printf("TRACE: SymGetLineFromAddr64 returned error: %d\n", error);
						}
					}
				}
			}
			coverage_report.covered_tests.push_back(test_coverage);
		}
	}
	// Cleanup symbol handler.
	if (symbol_handler_initialized && current_proc_handle) {
		printf("DEBUG: Done with symbol handler, cleaning up now...\n");
		SymCleanup(current_proc_handle);
	}
	printf("DEBUG: Writing collected coverage to output file %s.\n", coverage_report.output_file.string().c_str());
	coverage_report.SaveAsCSV();
	coverage_report.SaveAsLCOV();

	return 0;
}