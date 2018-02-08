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
#ifdef _WIN64
	pImage->FileHeader = (PIMAGE_NT_HEADERS64)(lpBuffer + pDosHeader->e_lfanew);
#else
	pImage->FileHeader = (PIMAGE_NT_HEADERS32)(lpBuffer + pDosHeader->e_lfanew);
#endif // _WIN64
	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
	pImage->Sections = IMAGE_FIRST_SECTION(pImage->FileHeader);
	return pImage;
}


//#ifdef _WIN64
//	PLOADED_IMAGE GetLoadedImage(DWORD64 dwImageBase)
//#else
//	PLOADED_IMAGE GetLoadedImage(DWORD dwImageBase)
//#endif // _WIN64
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
//未完成修复等工作，目前不使用
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