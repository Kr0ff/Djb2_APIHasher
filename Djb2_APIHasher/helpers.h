#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include "structs.h"
#include "algos.h"

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
PBYTE GetModuleBaseAddress(wchar_t* pModuleName);
PBYTE VerifyHashString(PBYTE FunctionName, DWORD64 dwHash);

PBYTE VerifyHashString(PBYTE FunctionName, DWORD64 dwHash) {

	const wchar_t* ntdll = L"ntdll.dll";
	PBYTE baseAddressNtDll = GetModuleBaseAddress((wchar_t*)L"ntdll.dll");

	printf("[+] NTDLL BASE ADDRESS \t( %#p )\n", baseAddressNtDll);

	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)baseAddressNtDll;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] IMAGE_DOS_SIGNATURE == FALSE\n");
		return FALSE;
	}
	else {
		printf("[+] IMAGE_DOS_SIGNATURE == TRUE\n");
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)baseAddressNtDll + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-] IMAGE_NT_SIGNATURE == FALSE\n");
		return FALSE;
	}
	else {
		printf("[+] IMAGE_NT_SIGNATURE == TRUE\n");
	}

	// Get the EAT
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)baseAddressNtDll + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	printf("\n[&] IMAGE_EXPORT_DIRECTORY == %#x\n", pImageExportDirectory);
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)baseAddressNtDll + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)baseAddressNtDll + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinals = (PWORD)((PBYTE)baseAddressNtDll + pImageExportDirectory->AddressOfNameOrdinals);

	printf("\
\t> AddressOfFunctions == %#lx\n\
\t> AddressOfNames == %#lx \n\
\t> AddressOfNameOrdinals == %#lx\n", pdwAddressOfFunctions, pdwAddressOfNames, pwAddressOfNameOrdinals);

	printf("\n\t================ LOOP ================\n\n");
	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)baseAddressNtDll + pdwAddressOfNames[cx]);
		size_t dwFunctionNameLen = strlen(pczFunctionName); // FOR JOAA hashing alg
		PVOID pFunctionAddress = (PBYTE)baseAddressNtDll + pdwAddressOfFunctions[pwAddressOfNameOrdinals[cx]];

		if (CRC32B((PBYTE)pczFunctionName) == dwHash) {
			printf("[+] FOUND !\n\
\t> FunctionName ( %s ) | FunctionAddress ( %#p )\n", pczFunctionName, pFunctionAddress);
			break;
		}
	}
}


PBYTE GetModuleBaseAddress(wchar_t* pModuleName) {

	PBYTE pModuleBase = 0;

	MODULEENTRY32 modEntry = {};
	modEntry.dwSize = sizeof(MODULEENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		CloseHandle(hSnapshot);
		return 0;
	}

	if (Module32FirstW(hSnapshot, &modEntry)) {
		do {
			if (lstrcmpiW(modEntry.szModule, pModuleName) == 0) {
				pModuleBase = modEntry.modBaseAddr;
				break;
			}
		} while (Module32NextW(hSnapshot, &modEntry));
	}
	else {
		CloseHandle(hSnapshot);
		return 0;
	}

	CloseHandle(hSnapshot);
	return pModuleBase;

}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

