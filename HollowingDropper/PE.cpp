#include "stdafx.h"
#include "PE.h"


LPVOID FindRemotePEB(HANDLE hProcess)
{
	HMODULE hNTDLL = LoadLibraryA("ntdll");
	if (!hNTDLL)
		cout << "-->Load ntdll.dll Failed." << endl;
	FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
	if (!fpNtQueryInformationProcess)
		return 0;
	PROCESS_BASIC_INFORMATION* pProcessInformation = new PROCESS_BASIC_INFORMATION();
	_NtQueryInformationProcess ntQueryInfomationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	DWORD dwReturnLength = 0;
	ntQueryInfomationProcess(hProcess, 0, pProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
	return pProcessInformation->PebBaseAddress;
}


_PPEB ReadRemotePEB(HANDLE hProcess)
{
	LPVOID dwPEBAddress = FindRemotePEB(hProcess);
	_PPEB pPEB = new _PEB();
	BOOL bSuccess = ReadProcessMemory(hProcess, dwPEBAddress, pPEB, sizeof(__PEB), 0);
	if (!bSuccess)
		return NULL;
	return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPVOID lpImageBaseAddress)
{
	BYTE* lpBuffer = new BYTE[BUFFER_SIZE];
	BOOL bSuccess = ReadProcessMemory(hProcess, lpImageBaseAddress, lpBuffer, BUFFER_SIZE, 0);
	if (!bSuccess)
		return NULL;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	PLOADED_IMAGE pImage = new LOADED_IMAGE();
	pImage->FileHeader = (PIMAGE_NT_HEADERS)(lpBuffer + pDosHeader->e_lfanew);

	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
	pImage->Sections = IMAGE_FIRST_SECTION(pImage->FileHeader);
	return pImage;
}


PLOADED_IMAGE GetLoadedImage(ULONG_PTR dwImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);
	PLOADED_IMAGE pImage = new LOADED_IMAGE();
	pImage->FileHeader = pNTHeaders;
	pImage->NumberOfSections = pNTHeaders->FileHeader.NumberOfSections;
	pImage->Sections = IMAGE_FIRST_SECTION(pNTHeaders);
	return pImage;
}
BOOL CopySections(HANDLE hProcess,ULONG_PTR targetBaseAddress,ULONG_PTR srcBuffer)
{
	int i, section_size;
	PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)(srcBuffer + ((PIMAGE_DOS_HEADER)srcBuffer)->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(header);//第一个节
	LPVOID dest;
	LPVOID buffer;
	ULONG_PTR ValueA;
	ULONG_PTR ValueB;
	ULONG_PTR ValueC;
	for (i = 0; i < header->FileHeader.NumberOfSections; i++, section++)
	{
		if (section->SizeOfRawData == 0)
		{
			section_size = header->OptionalHeader.SectionAlignment;
			if (section_size > 0)
			{
				dest = VirtualAllocEx(hProcess, (LPVOID)(targetBaseAddress + section->VirtualAddress), section_size, MEM_COMMIT, PAGE_READWRITE);
				if (dest = NULL)
					return FALSE;
				dest = (LPVOID)(targetBaseAddress + section->VirtualAddress);
				//保存在当前进程缓冲区内，避免多次读写目标进程内存
				section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
			}
			continue;
		}
		dest = VirtualAllocEx(hProcess, (LPVOID)(targetBaseAddress + section->VirtualAddress), section->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
		ValueA = section->SizeOfRawData;
		//当前节数据的缓冲区
		PBYTE currentSectionData = new BYTE[ValueA];
		ValueB = srcBuffer + section->PointerToRawData;
		ValueC = (ULONG_PTR)currentSectionData;
		while (ValueA--)
			*(BYTE *)ValueC++ = *(BYTE *)ValueB++;
		if (!WriteProcessMemory
		(
			hProcess,
			dest,
			(LPVOID)currentSectionData,
			section->SizeOfRawData,
			NULL
		))
			return FALSE;
		dest = (LPVOID)(targetBaseAddress + section->VirtualAddress);
		section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
	}
	return TRUE;
}

static ULONG_PTR
GetRealSectionSize(PIMAGE_NT_HEADERS header, PIMAGE_SECTION_HEADER section) {
	DWORD size = section->SizeOfRawData;
	if (size == 0) {
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = header->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = header->OptionalHeader.SizeOfUninitializedData;
		}
	}
	return (ULONG_PTR)size;
}


static inline ULONG_PTR
AlignValueDown(ULONG_PTR value, ULONG_PTR alignment)
{
	return value & ~(alignment - 1);
}
//0x1000 - 1 = 0xfff 取反后，后三位为0，与运算后的结果为后三位舍为0的值，即为向下取整
static inline LPVOID
AlignAddressDown(LPVOID address, ULONG_PTR alignment)
{
	return (LPVOID)AlignValueDown((ULONG_PTR)address, alignment);
}
static int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{ PAGE_NOACCESS, PAGE_WRITECOPY },
		{ PAGE_READONLY, PAGE_READWRITE },
	},{
		// executable
		{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
		{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
	},
};

static BOOL
FinalizeSection(HANDLE hProcess,PIMAGE_NT_HEADERS header, PSECTIONFINALIZEDATA sectionData,SYSTEM_INFO sysInfo)
{
	DWORD protect, oldProtect;
	BOOL executable;
	BOOL readable;
	BOOL writeable;

	if (sectionData->size == 0) {
		return TRUE;
	}
	//IMAGE_SCN_MEM_DISCARDABLE:可以根据需要丢弃，不再被使用，可以安全释放掉
	if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
		//确保释放当前页没有问题
		if (sectionData->address == sectionData->alignedAddress &&
			(sectionData->last ||
				header->OptionalHeader.SectionAlignment == sysInfo.dwPageSize ||
				(sectionData->size % sysInfo.dwPageSize) == 0)
			) {
			//释放
			VirtualFreeEx(hProcess, sectionData->address, sectionData->size, MEM_DECOMMIT);
		}
		return TRUE;
	}

	// determine protection flags based on characteristics
	executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
	readable = (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
	writeable = (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
	protect = ProtectionFlags[executable][readable][writeable];
	if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
		protect |= PAGE_NOCACHE;
	}

	//修改访问权限
	if (VirtualProtectEx(hProcess, sectionData->address, sectionData->size, protect, &oldProtect) == 0)
	{
		cout << "Change Memory Access Flag Failed." << endl;
		return FALSE;
	}
	return TRUE;
}

BOOL FinalizeSections(HANDLE hProcess, ULONG_PTR targetBaseAddress, ULONG_PTR srcBuffer)
{
	int i, section_size;
	PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)(srcBuffer + ((PIMAGE_DOS_HEADER)srcBuffer)->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(header);//第一个节
	//和Memory Module一样，这里地址被截断
#ifdef _WIN64
	ULONG_PTR imageOffset = (ULONG_PTR)(header->OptionalHeader.ImageBase) & 0xffffffff00000000;
#else
	ULONG_PTR imageOffset = 0;
#endif // _WIN64
	SECTIONFINALIZEDATA sectionData;
	sectionData.address = (LPVOID)(((DWORD)section->Misc.PhysicalAddress) | imageOffset);
	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);
	//向下对齐地址，节首地址
	sectionData.alignedAddress = AlignAddressDown(sectionData.address, sysInfo.dwPageSize);
	//实际大小
	sectionData.size = GetRealSectionSize(header, section);
	//属性
	sectionData.characteristics = section->Characteristics;
	sectionData.last = FALSE;

	for (i = 1; i < header->FileHeader.NumberOfSections; i++, section++)
	{
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
		LPVOID alignedAddress = AlignAddressDown(sectionAddress, sysInfo.dwPageSize);
		ULONG_PTR sectionSize = GetRealSectionSize(header, section);

		if (sectionData.alignedAddress == alignedAddress || (ULONG_PTR)sectionData.address + sectionData.size > (ULONG_PTR)alignedAddress)
		{
			if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			}
			else {
				sectionData.characteristics |= section->Characteristics;
			}
			sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.address;
			continue;
		}
		if (!FinalizeSection(hProcess, header,&sectionData,sysInfo)) {
			return FALSE;
		}
		sectionData.address = sectionAddress;
		sectionData.alignedAddress = alignedAddress;
		sectionData.size = sectionSize;
		sectionData.characteristics = section->Characteristics;
	}
	sectionData.last = TRUE;
	if (!FinalizeSection(hProcess, header, &sectionData, sysInfo)) {
		return FALSE;
	}
	return TRUE;
}