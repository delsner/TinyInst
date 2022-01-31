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
	std::string test_identifier;
	std::string module_name;
	uint64_t offset;
	std::string filename;
	int line_number;
};

struct CoverageReport {
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
				<< std::dec << covered_address.line_number << "\n";
		}
		file_stream.close();
	}
};

// Main routine.
int main(int argc, char** argv)
{
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
		printf("-ext <file extension for coverage files>\n");
		printf("\tdefault: .cov\n");
		printf("-regex <regex for included files>\n");
		printf("\tdefault: .*\n");
		printf("-root <root path to search for coverage files>\n");
		printf("\tdefault: current working directory\n");
		printf("-symbol_path <symbol path for covered module>\n");
		printf("\trequired: provide at least one symbol path (searched recursively)\n");
		printf("-output <output CSV filename>\n");
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
	CoverageReport coverageReport;
	coverageReport.output_file = output_file;
	HANDLE current_proc_handle = GetCurrentProcess();
	printf("DEBUG: Using current process handle %d\n", current_proc_handle);
	bool symbol_handler_initialized = false;
	std::map<std::string, uint64_t> loaded_modules;
	for (const auto& path : fs::directory_iterator(root)) {
		if (path.path().extension() == ext) {
			std::ifstream is(path.path());
			std::string line;
			while (std::getline(is, line))
			{
				// Look up symbol and store (test_id, module_name, offset, file, line) into coverage report
				std::size_t module_name_len = line.find("+");
				if (module_name_len != std::string::npos) {
					CoveredAddress covered_address;
					covered_address.test_identifier = path.path().stem().string();
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
						if (std::regex_match(covered_address.filename, regex)) {
							printf("DEBUG: Adding filename (%s) due to regex match.\n", covered_address.filename.c_str());
							coverageReport.covered_addresses.push_back(covered_address);
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
		}
	}
	// Cleanup symbol handler.
	if (symbol_handler_initialized && current_proc_handle) {
		printf("DEBUG: Done with symbol handler, cleaning up now...\n");
		SymCleanup(current_proc_handle);
	}
	printf("DEBUG: Writing collected coverage to output file %s.\n", coverageReport.output_file.string().c_str());
	coverageReport.WriteToFile();
	// TODO: Add other export strategy here for standardized output format, e.g., to visualize line coverage.

	return 0;
}