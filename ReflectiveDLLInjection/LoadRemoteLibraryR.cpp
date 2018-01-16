#include "LoadRemoteLibraryR.h"
#include <iostream>
using namespace std;
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	//得到nt头在内存中的实际地址
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	//获得节表
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	//不在任意块内
	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;
	//通过遍历块，来找到相对偏移地址对应的文件偏移地址
	for (WORD wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
	
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
			//		\------------------块内偏移-------------------/	\-----------块在文件中的偏移------------/
	}
}
DWORD GetReflectiveLoaderOffset(VOID * lpReflectiveDllBuffer)
{
	//基址->在Dropper进程中开辟的堆空间
	UINT_PTR uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
	//得到NT头的文件地址
	UINT_PTR uiExportDir = (UINT_PTR)uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
	//获得导出表结构体指针的地址
	UINT_PTR uiNameArray = (UINT_PTR)&(((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	//该调用中，第一个参数即为导出表结构体映射到内存的相对虚拟地址
	//结果为找到到导出表结构体的内存地址
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);
	//得到导出表名称数组在内存中的地址RVA
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);
	//得到导出函数地址表在内存中的地址RVA
	UINT_PTR uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);
	//得到函数序号地址表在内存中的地址
	UINT_PTR uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);
	//导出函数的数量
	DWORD dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	while (dwCounter--)
	{
		//这里需要将获取到的各表的RVA转化为各表实际的文件偏移
		char *cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset((*(DWORD*)uiNameArray), uiBaseAddress));
		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			//获取地址表起始地址的实际位置
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);
			//根据序号找到序号对应的函数地址
			uiAddressArray += (*(WORD*)(uiNameOrdinals) * sizeof(DWORD));

			// 返回ReflectiveLoader函数的文件偏移，即函数机器码的起始地址
			return Rva2Offset((*(DWORD*)uiAddressArray), uiBaseAddress);
		}
		uiNameArray += sizeof(DWORD);
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}




HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter)
{
	//HMODULE hResult = NULL;
	DWORD dwThreadId;
	HANDLE hThread = NULL;
	__try
	{

		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
				break;
			//检查dll是否被反射加载
			DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
				break;
			//在目标进程分配内存（RWX）
			LPVOID lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;
			//线程函数的地址=基地址+文件偏移
			LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);
			

			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

		} while (0);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	
		hThread = NULL;
	}
	return hThread;
}