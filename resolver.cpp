#include <stdio.h>
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>

#include "common.h"
#include "dbghelp.h"

namespace fs = std::filesystem;

// Utils.
BOOL CALLBACK EnumSymProc(
	PSYMBOL_INFO pSymInfo,
	ULONG SymbolSize,
	PVOID UserContext)
{
	UNREFERENCED_PARAMETER(UserContext);

	printf("0x%llx %4u %s\n",
		pSymInfo->Address, SymbolSize, pSymInfo->Name);
	return TRUE;
}

BOOL CALLBACK EnumModules(
	PCTSTR  ModuleName,
	DWORD64 BaseOfDll,
	PVOID   UserContext)
{
	UNREFERENCED_PARAMETER(UserContext);

	printf("0x%llx %s\n", BaseOfDll, ModuleName);
	return TRUE;
}

// Main routine.
int main(int argc, char** argv)
{
	char* image_arg = GetOption("-image", argc, argv);
	std::string image_path;
	if (image_arg)
		image_path = std::string(image_arg);
	else
		image_path = std::string(".");

	if (argc < 2) {
		printf("Usage:\n");
		printf("%s [options]\n", argv[0]);
		printf("\n");
		printf("Options:\n");
		printf("-image <image file to analyze (.exe, .dll, .sym)>\n");
		return 0;
	}

	// Join symbol paths to user symbol search path.
	std::string symbol_search_path(fs::path(image_path).parent_path().string() + ";");
	symbol_search_path += ".;";
	symbol_search_path += "SRV*c:\\symbolcache*https://msdl.microsoft.com/download/symbols";
	HANDLE current_proc_handle = GetCurrentProcess();

	// Init symbol handler.
	DWORD error;
	SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
	printf("DEBUG: Initializing symbol handler with search path: %s\n", symbol_search_path.c_str());
	if (!SymInitialize(
		current_proc_handle,                // Current process handle, although this simply has to be a UID.
		symbol_search_path.c_str(),         // User search path for symbols, semicolon-separated list of symbol modules (search for symbol files is done recursively).
		FALSE)) {                            // fInvadeProcess is set to false, to prevent loading symbols for all already loaded modules.
		error = GetLastError();
		printf("ERROR: SymInitialize returned error: %d\n", error);
		SymCleanup(current_proc_handle);
		return 1;
	}

	printf("DEBUG: Starting to load module: %s\n", image_path.c_str());
	DWORD64 dwBaseAddr = 0;
	DWORD64 dwDllBase = SymLoadModuleEx(
		current_proc_handle,                    // target process 
		NULL,                                   // handle to image - not used
		image_path.c_str(),                     // name of image file (can be a name that is resolved through the symbol handler path)
		NULL,                                   // name of module - not required
		dwBaseAddr,                             // base address - not required (set to 0 here)
		0,                                      // size of image - not required
		NULL,                                   // MODLOAD_DATA used for special cases 
		0);
	if (!dwDllBase) {
		error = GetLastError();
		if (error != ERROR_SUCCESS) {
			printf("ERROR: SymLoadModuleEx returned error: %d\n", error);
			SymCleanup(current_proc_handle);
			return 1;
		}
	}
	else {
		printf("DEBUG: Successfully loaded module (base address): %s (0x%llx)\n", image_path.c_str(), dwDllBase);
		// In order to trigger deferred symbol loading, get module info.
		_IMAGEHLP_MODULE64 moduleInfo;
		moduleInfo.SizeOfStruct = sizeof(_IMAGEHLP_MODULE64);
		printf("DEBUG: Trigger loading module info.\n");
		if (SymGetModuleInfo64(current_proc_handle, dwDllBase, &moduleInfo)) {
			printf("DEBUG: Loaded module info, image name (%s), base address (0x%llx)\n",
				moduleInfo.ImageName, moduleInfo.BaseOfImage);
		}

		if (SymEnumerateModules64(current_proc_handle, EnumModules, NULL))
		{
			// SymEnumerateModules64 returned success
		}
		else
		{
			error = GetLastError();
			printf("SymEnumerateModules64 returned error : %d\n", error);
		}
		if (SymEnumSymbols(current_proc_handle,     // Process handle from SymInitialize.
			dwDllBase,								// Base address of module.
			"Foo*",						// Name of symbols to match.
			EnumSymProc,							// Symbol handler procedure.
			NULL))									// User context.
		{
			// SymEnumSymbols succeeded
		}
		else
		{
			error = GetLastError();
			printf("SymEnumSymbols failed: %d\n", GetLastError());
		}
	}

	DWORD dwDisplacement;
	IMAGEHLP_LINE64 symbol_line;
	memset(&symbol_line, 0x0, sizeof(symbol_line));
	symbol_line.SizeOfStruct = sizeof(symbol_line);
	printf("DEBUG: Looking up symbol at address: %llx (%llx + %llx)\n", (dwDllBase + 0x1af80), dwDllBase, 0x1af80);
	if (SymGetLineFromAddr64(current_proc_handle, dwDllBase + 0x1af80, &dwDisplacement, &symbol_line)) {
		printf("DEBUG: Found filename (%s) and line (%d)\n", symbol_line.FileName, symbol_line.LineNumber);
	}
	else {
		error = GetLastError();
		if (error != ERROR_SUCCESS) {
			printf("ERROR: SymGetLineFromAddr64 returned error: %d\n", error);
			SymCleanup(current_proc_handle);
			return 1;
		}
	}

	// Cleanup symbol handler.
	SymCleanup(current_proc_handle);
	return 0;
}