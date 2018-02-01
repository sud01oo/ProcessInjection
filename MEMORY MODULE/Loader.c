#include "Loader.h"
HINSTANCE hAppInstance = NULL;
ULONG_PTR WINAPI Loader(ULONG_PTR callAddress)
{
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
	USHORT usCounter;
	ULONG_PTR uiLibraryAddress;
	ULONG_PTR uiBaseAddress;
	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	uiLibraryAddress = callAddress + 10;
	//通过遍历内存地址，找到文件在内存中的起始地址
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			//pe头偏移RVA
			uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			//判断PE头的正确性
			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				//pe头在内存中的位置
				uiHeaderValue += uiLibraryAddress;
				// break if we have found a valid MZ/PE header
				//如果找到文件头就退出循环
				if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		uiLibraryAddress--;
	}
	//处理我们loader需要的内核导出表
	// STEP 1: process the kernels exports for the functions our loader needs...
	//获得PEB,64位下，GS指向段内存的0x60偏移处就是peb结构的位置，32位下位FS:[0x30]
	// get the Process Enviroment Block
	uiBaseAddress = __readgsqword(0x60);//uiBaseAddress -> peb
										//获取进程加载模块
										// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;//uiBaseAddress->pLdr
															//获取第一个“内存顺序”模块列表入口
															// get the first entry of the InMemoryOrder module list
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;//uiBaseAddress->PLDR_DATA_TABLE_ENTRY
	while (uiValueA)
	{
		// get pointer to current modules name (unicode string)
		//当前模块名地址
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		uiValueC = 0;
		//计算模块名的hash
		// compute the hash of the module name...
		do
		{
			uiValueC = ror((DWORD)uiValueC);
			// normalize to uppercase if the madule name is in lowercase
			if (*((BYTE *)uiValueB) >= 'a')
				uiValueC += *((BYTE *)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE *)uiValueB);
			uiValueB++;
		} while (--usCounter);
		//获取kerlnel32中的函数地址
		// compare the hash with that of kernel32.dll
		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 3;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
					//获取函数地址
					// store this functions VA
					if (dwHashValue == LOADLIBRARYA_HASH)
						pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == GETPROCADDRESS_HASH)
						pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALALLOC_HASH)
						pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
		else if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			//与之前解析PE结构相同
			// get this modules base address
			uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

			// get the VA of the modules NT Header
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

			// uiNameArray = the address of the modules export directory entry
			uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

			// get the VA of the export directory
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			// get the VA for the array of name pointers
			uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

			usCounter = 1;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
				{
					// get the VA for the array of addresses
					uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));

					// decrement our counter
					usCounter--;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}

		// we stop searching when we have found everything we need.
		if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
			break;

		// get the next entry
		uiValueA = DEREF(uiValueA);
	}//end while
	 //NT头的虚拟地址，原DLL文件中
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
	//基地址
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//增加的一些判断
	if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	/*
		这里可以有一些校验，让加载变得更准确，避免出错。
	*/
	//对齐粒度，应该是2的倍数
	if (((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SectionAlignment & 1)
	{
		return NULL;
	}
}