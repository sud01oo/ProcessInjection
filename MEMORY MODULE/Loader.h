#include <Windows.h>
#include <intrin.h>
#include <winnt.h>
typedef HMODULE(WINAPI * LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI * GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI * VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI * NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

//HASH算法依旧使用原项目
#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8


#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define HASH_KEY						13
#pragma intrinsic( _rotr )
__forceinline DWORD ror(DWORD d)
{
	return _rotr(d, HASH_KEY);
}
__forceinline DWORD hash(char * c)
{
	register DWORD h = 0;
	do
	{
		h = ror(h);
		h += *c;
	} while (*++c);

	return h;
}

//以下为一些peb相关数据结构
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK * pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STR ImagePathName;
	UNICODE_STR CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
//根据在反射式DLL注射中所描述的，由于字节对齐的原因，使用被注释掉的结构和目前用的结构是相同的结果
typedef struct __PEB // 65 elements, 0x210 bytes
{
	//BYTE bInheritedAddressSpace;
	//BYTE bReadImageFileExecOptions;
	//BYTE bBeingDebugged;
	//BYTE bSpareBool;
	//LPVOID lpMutant;
	//LPVOID lpImageBaseAddress;
	//PPEB_LDR_DATA pLdr;
	//LPVOID lpProcessParameters;
	//LPVOID lpSubSystemData;
	//LPVOID lpProcessHeap;
	//PRTL_CRITICAL_SECTION pFastPebLock;
	//LPVOID lpFastPebLockRoutine;
	//LPVOID lpFastPebUnlockRoutine;
	//DWORD dwEnvironmentUpdateCount;
	//LPVOID lpKernelCallbackTable;
	//DWORD dwSystemReserved;
	//DWORD dwAtlThunkSListPtr32;
	//PPEB_FREE_BLOCK pFreeList;
	//DWORD dwTlsExpansionCounter;
	//LPVOID lpTlsBitmap;
	//DWORD dwTlsBitmapBits[2];
	//LPVOID lpReadOnlySharedMemoryBase;
	//LPVOID lpReadOnlySharedMemoryHeap;
	//LPVOID lpReadOnlyStaticServerData;
	//LPVOID lpAnsiCodePageData;
	//LPVOID lpOemCodePageData;
	//LPVOID lpUnicodeCaseTableData;
	//DWORD dwNumberOfProcessors;
	//DWORD dwNtGlobalFlag;
	//LARGE_INTEGER liCriticalSectionTimeout;
	//DWORD dwHeapSegmentReserve;
	//DWORD dwHeapSegmentCommit;
	//DWORD dwHeapDeCommitTotalFreeThreshold;
	//DWORD dwHeapDeCommitFreeBlockThreshold;
	//DWORD dwNumberOfHeaps;
	//DWORD dwMaximumNumberOfHeaps;
	//LPVOID lpProcessHeaps;
	//LPVOID lpGdiSharedHandleTable;
	//LPVOID lpProcessStarterHelper;
	//DWORD dwGdiDCAttributeList;
	//LPVOID lpLoaderLock;
	//DWORD dwOSMajorVersion;
	//DWORD dwOSMinorVersion;
	//WORD wOSBuildNumber;
	//WORD wOSCSDVersion;
	//DWORD dwOSPlatformId;
	//DWORD dwImageSubsystem;
	//DWORD dwImageSubsystemMajorVersion;
	//DWORD dwImageSubsystemMinorVersion;
	//DWORD dwImageProcessAffinityMask;
	//DWORD dwGdiHandleBuffer[34];
	//LPVOID lpPostProcessInitRoutine;
	//LPVOID lpTlsExpansionBitmap;
	//DWORD dwTlsExpansionBitmapBits[32];
	//DWORD dwSessionId;
	//ULARGE_INTEGER liAppCompatFlags;
	//ULARGE_INTEGER liAppCompatFlagsUser;
	//LPVOID lppShimData;
	//LPVOID lpAppCompatInfo;
	//UNICODE_STR usCSDVersion;
	//LPVOID lpActivationContextData;
	//LPVOID lpProcessAssemblyStorageMap;
	//LPVOID lpSystemDefaultActivationContextData;
	//LPVOID lpSystemAssemblyStorageMap;
	//DWORD dwMinimumStackCommit;
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PPEB_LDR_DATA pLdr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved3[520];
	//PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved4[136];
	ULONG SessionId;
} _PEB, *_PPEB;

//
typedef struct _LDR_DATA_TABLE_ENTRY
{
	//LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//标志，重定位类型
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;


#ifdef __cplusplus
extern "C" {
#endif
	ULONG_PTR WINAPI ReflectiveLoader(ULONG_PTR callAddress);
#ifdef __cplusplus
}
#endif