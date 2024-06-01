#include <stdio.h>
#include "helpers.h"
#include "algos.h"

// WMAIN is required for hashing strings for GetModuleHandle
//int main(int argc, char* argv[]) {
int main(int argc, char* argv[]) {

	if (argc < 3) {
		printf("Usage: tool.exe <Module> <FunctionName>\n");
		printf("Modules: \n\t- kernel32\n\t- ntdll");
		return 0x1;
	}

	//char* szFunctionName = argv[1];
	char* szModule			= argv[1];
	char* szFunctionName	= argv[2];

	//USHORT lenStr = strlen(szFunctionName);
	
	//DWORD64 dwHashDJB2 = djb2((PBYTE)szFunctionName);
	//DWORD64 dwHashJOAA = JOAA((PBYTE)szFunctionName, lenStr);
	//DWORD64 dwHashKRv2 = KR_v2_hash((PBYTE)szFunctionName);
	//DWORD64	dwHashCoffin = Coffin_hash((PBYTE)szFunctionName);
	DWORD64	dwHashCRC32B = CRC32B((PBYTE)szFunctionName);

	//printf("[DJB2]    %s  -> %#llx\n", szFunctionName, dwHash);
	//printf("[JOAA]    %s (%d) -> %#llx\n", szFunctionName, lenStr, JOAA_);
	//printf("[Coffin]  %s  -> %#llx\n", szFunctionName, dwHashCoffin);
	//printf("[KR_V2]	  %s  -> %#llx\n", szFunctionName, dwHashKRv2);
	printf("[MODULE]    USING -> %s\n", szModule);
	printf("[CRC32B]    %s -> %#llx\n", szFunctionName, dwHashCRC32B);

	/*
	PBYTE K32basePtr = GetModuleBaseAddress((wchar_t*)L"kernel32.dll");
	PBYTE NtbasePtr = GetModuleBaseAddress((wchar_t*)L"ntdll.dll");

	printf("Module Base \n\t-> KERNEL32: %#p\n\t-> NTDLL: %#p\n", K32basePtr, NtbasePtr);
	*/ 

	printf("\tPress Enter To Verify\n");
	getchar();

	if (lstrcmpA(szModule, "ntdll") == 0) {
		NTVerifyHashString((PBYTE)szFunctionName, dwHashCRC32B);
	}
	else if (lstrcmpA(szModule, "kernel32") == 0) {
		K32VerifyHashString((PBYTE)szFunctionName, dwHashCRC32B);
	}
	else {
		return -2;
	}

	getchar();
	return 0x0;

}