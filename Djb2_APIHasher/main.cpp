#include <stdio.h>
#include "helpers.h"
#include "algos.h"

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Usage: tool.exe <NtFunctionName>\n");
		return 0x1;
	}

	char* szFunctionName = argv[1];

	DWORD64 dwHash = djb2((PBYTE)szFunctionName);
	// DWORD64 dwHashKRv2 = KR_v2_hash((PBYTE)szFunctionName);
	// DWORD64	dwHashCoffin = Coffin_hash((PBYTE)szFunctionName);

	printf("[DJB2]    %s  -> %#llx\n", szFunctionName, dwHash);
	// printf("[Coffin]  %s  -> %#llx\n", szFunctionName, dwHashCoffin);
	// printf("[KR_V2]	  %s  -> %#llx\n", szFunctionName, dwHashKRv2);
	
	printf("\tPress Enter To Verify\n");
	getchar();

	VerifyHashString((PBYTE)szFunctionName, dwHash);

	return 0x0;

}