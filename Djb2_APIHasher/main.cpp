#include <stdio.h>
#include "helpers.h"
#include "algos.h"

// WMAIN is required for hashing strings for GetModuleHandle
//int main(int argc, char* argv[]) {
int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Usage: tool.exe <NtFunctionName>\n");
		return 0x1;
	}

	//char* szFunctionName = argv[1];
	char* szFunctionName = argv[1];

	//USHORT lenStr = strlen(szFunctionName);
	
	//DWORD64 dwHashDJB2 = djb2((PBYTE)szFunctionName);
	//DWORD64 dwHashJOAA = JOAA((PBYTE)szFunctionName, lenStr);
	// DWORD64 dwHashKRv2 = KR_v2_hash((PBYTE)szFunctionName);
	// DWORD64	dwHashCoffin = Coffin_hash((PBYTE)szFunctionName);
	DWORD64	dwHashCRC32B = CRC32B((PBYTE)szFunctionName);

	//printf("[DJB2]    %s  -> %#llx\n", szFunctionName, dwHash);
	
	//printf("[JOAA]    %s (%d) -> %#llx\n", szFunctionName, lenStr, JOAA_);
	
	// printf("[Coffin]  %s  -> %#llx\n", szFunctionName, dwHashCoffin);
	
	// printf("[KR_V2]	  %s  -> %#llx\n", szFunctionName, dwHashKRv2);
	
	printf("[CRC32B]    %s -> %#llx\n", szFunctionName, dwHashCRC32B);
	
	printf("\tPress Enter To Verify\n");
	getchar();

	VerifyHashString((PBYTE)szFunctionName, dwHashCRC32B);

	getchar();
	return 0x0;

}