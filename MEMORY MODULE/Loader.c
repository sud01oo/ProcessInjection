#include "Loader.h"
HINSTANCE hAppInstance = NULL;

// Protection flags for memory pages (Executable, Readable, Writeable)
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
DWORD AlignValueUp(DWORD value, DWORD alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

uintptr_t
AlignValueDown(uintptr_t value, uintptr_t alignment) {
	return value & ~(alignment - 1);
}

LPVOID
AlignAddressDown(LPVOID address, uintptr_t alignment) {
	return (LPVOID)AlignValueDown((uintptr_t)address, alignment);
}


SIZE_T
GetRealSectionSize(PMemoryModule module, PIMAGE_SECTION_HEADER section,PIMAGE_NT_HEADERS header) {
	DWORD size = section->SizeOfRawData;
	if (size == 0) {
		//判断节属性
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size = header->OptionalHeader.SizeOfInitializedData;
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size = header->OptionalHeader.SizeOfUninitializedData;//所有含未初始化数据的节的大小
		}
	}
	return (SIZE_T)size;
}

BOOL CopySections(PIMAGE_NT_HEADERS srcHeader, PIMAGE_NT_HEADERS targetHeader,ULONG_PTR srcAddress,ULONG_PTR targetAddress,PMemoryModule mModule)
{
	int i, section_size;
	ULONG_PTR dest;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(srcHeader); 
	DWORD ValueA;
	DWORD ValueB;
	DWORD ValueC;
	for (i = 0; i < targetHeader->FileHeader.NumberOfSections; i++, section++)
	{
		//在DLL中，当前节不含有数据，但是可能定义未初始化的数据
		if (section->SizeOfRawData == 0)
		{
			//内存中节的对齐粒度
			section_size = srcHeader->OptionalHeader.SectionAlignment;
			if (section_size > 0)
			{
				dest = mModule->mVirutalAlloc(targetAddress, section_size, MEM_COMMIT, PAGE_READWRITE, NULL);//mModule->flProtect);
				if (dest == NULL)
					return FALSE;
				//始终保持页对齐，以上分配的内存，正好为一页
				dest = targetAddress + section->VirtualAddress;
				//64位模式下，这里截断成32位模式
				section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
			}
			//section 为空
			continue;
		}

		//节中含有数据
		dest = mModule->mVirutalAlloc(targetAddress + section->VirtualAddress, section->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE, NULL);
		//
		ValueA = section->SizeOfRawData;//节的大小
		ValueB = targetAddress + section->PointerToRawData;//数据的起始地址
		ValueC = dest;//数据将被拷贝到到的地址
								 //复制头和节表的数据到新开辟的缓冲区
		while (ValueA--)
			*(BYTE *)ValueC++ = *(BYTE *)ValueB++;

		if (dest == NULL)
			return FALSE;
		dest = targetAddress + section->VirtualAddress;
		
		section->Misc.PhysicalAddress = (DWORD)((uintptr_t)dest & 0xffffffff);
	}//end for
	return TRUE;
}
ULONG_PTR WINAPI Loader(ULONG_PTR callAddress)
{
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
	VIRTUALPROTECT pVirtualProtect = NULL;
	VIRTUALFREE pVirtualFree = NULL;
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

	//内存映射阶段用到
	PIMAGE_SECTION_HEADER section;
	DWORD optionalSectionSize;
	DWORD lastSectionEnd = 0;
	SYSTEM_INFO sysInfo;//获取页面大小用
	DWORD alignedImageSize;
	ULONG_PTR code;//address
	ULONG_PTR header;

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

			usCounter = 5;

			// loop while we still have imports to find
			while (usCounter > 0)
			{
				// compute the hash values for this function name
				dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

				// if we have found a function we want we get its virtual address
				if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH || dwHashValue == VIRTUALFREE_HASH || dwHashValue == VIRTUALPROCT_HASH)
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
					else if (dwHashValue == VIRTUALPROCT_HASH)
						pVirtualProtect = (VIRTUALPROTECT)(uiBaseAddress + DEREF_32(uiAddressArray));
					else if (dwHashValue == VIRTUALFREE_HASH)
						pVirtualFree = (VIRTUALFREE)(uiBaseAddress + DEREF_32(uiAddressArray));
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
	//uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
	//第一个节的地址
	section = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)uiHeaderValue);
	//内存中的节的对齐粒度
	optionalSectionSize = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SectionAlignment;
	//算出节最后的地址
	for (int i = 0; i < (((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections); i++, section++)
	{
		DWORD endOfSection;
		if (section->SizeOfRawData == 0)
		{
			//如果节中没有数据，则默认按照粒度分配一节
			endOfSection = section->VirtualAddress + optionalSectionSize;
		}
		else
		{
			//有数据，则加上正常的数据长度
			endOfSection = section->VirtualAddress + (section->SizeOfRawData);
		}

		if (endOfSection > lastSectionEnd)
		{
			lastSectionEnd = endOfSection;
		}
	}
	//sysInfo->dwPageSize=0x1000 ------4K
	GetNativeSystemInfo(&sysInfo);
	//Git上的MemoryModule代码中的对齐函数都为内联模式，不利于调试，这里我修改成正常的函数调用
	//param1:内存中的整个PE映像大小	param2：页面大小
	//计算镜像对齐的大小
	alignedImageSize = AlignValueUp(((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
	//所有节加起来后最后的地址对齐后一定和使用SizeOfImage对齐的大小是相同的
	if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize))
	{
		return NULL;
	}
	//先按照镜像建议的基址进行空间分配保留的的内存。(在Git上的项目中，是MEM_RESERVE|MEM_COMMIT)
	code = pVirtualAlloc((LPVOID)(((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase),
		alignedImageSize,
		MEM_RESERVE ,//| MEM_COMMIT,
		PAGE_READWRITE,
		NULL);
	//如果镜像占用的位置被占用，则选择其他位置。
	if (code == NULL)
	{
		code = pVirtualAlloc(NULL,
			alignedImageSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE,
			NULL);
		if (code == NULL)
		{
			return;
		}
	}
	uiBaseAddress = code;
	//提交内存
	header = pVirtualAlloc(code, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders,
		MEM_COMMIT,
		PAGE_READWRITE,
		NULL);
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;//所有头+节表的大小
	uiValueB = uiLibraryAddress;//DLL的起始地址，即缓冲区的起始地址
	uiValueC = code;//dll将被加载的地址的起始地址
					//复制头和节表的数据到新开辟的缓冲区
	//将镜像的加载地址写到PE头，不论是否在建议的地址加载
	((PIMAGE_NT_HEADERS)header)->OptionalHeader.ImageBase = code;
	while (uiValueA--)
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;
	PMemoryModule result = (PMemoryModule)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MemoryModule));
	result->mVirutalAlloc = pVirtualAlloc;
	//CopySections(PIMAGE_NT_HEADERS srcHeader, PIMAGE_NT_HEADERS targetHeader,ULONG_PTR srcAddress,ULONG_PTR targetAddress,PMemoryModule mModule)
	if (!CopySections((PIMAGE_NT_HEADERS)uiHeaderValue, (PIMAGE_NT_HEADERS)header, uiLibraryAddress, code, result))
	{
		return NULL;
	}

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	//基地址+RVA即导入表描述符的地址VA
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

	// itterate through all imports
	//链接库名字
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		//使用LoadLibraryA将需要的模块加载到内存
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		//指向INT的IMAGE_THUNK_DATA的VA
		uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		//要导入IAT的IMAGE_THUNK_DATA结构体
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// get the VA for the array of addresses
				uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = (uiBaseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)//INT
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	//程序建议的装载地址与实际装载地址的差
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
	//重定向表的地址
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)//重定位表大小
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		//重定位表的地址
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)//重定位块的大小
		{
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);//重定位内存页的起始RVA
																							//重定位块中的项数(整个块的大小减去结构体的大小，得到重定位项的总大小，除以每个重定位项的大小)
																							// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			//重定位块的第一项
			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);
			//遍历重定位项
			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				//重定位项的高四位代表此重定位项的类型
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;

				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);
				//下一个重定位项
				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}
			//下一个重定位块
			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}
	////释放标为“丢弃”的内存，依照节头修改内存属性
	

}

BOOL FinalizeSections(PIMAGE_NT_HEADERS header,PMemoryModule mMemory)
{
	int i;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(header);
#ifdef _WIN64
	// "PhysicalAddress" might have been truncated to 32bit above, expand to
	// 64bits again.
	//拷贝的时候被截断，这里恢复成64位
	uintptr_t imageOffset = ((uintptr_t)header->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
	static const uintptr_t imageOffset = 0;
#endif
	SECTIONFINALIZEDATA sectionData;
	sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
	sectionData.alignedAddress = AlignAddressDown(sectionData.address, mMemory->sysInfo.dwPageSize);
	sectionData.size = GetRealSectionSize(mMemory, section,header);
	sectionData.characteristics = section->Characteristics;
	sectionData.last = FALSE;
	section++;

	for (i = 1; i<header->FileHeader.NumberOfSections; i++, section++) {
		LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
		LPVOID alignedAddress = AlignAddressDown(sectionAddress, mMemory->sysInfo.dwPageSize);
		SIZE_T sectionSize = GetRealSectionSize(mMemory, section,header);
		// Combine access flags of all sections that share a page
		// TODO(fancycode): We currently share flags of a trailing large section
		//   with the page of a first small section. This should be optimized.
		if (sectionData.alignedAddress == alignedAddress || (uintptr_t)sectionData.address + sectionData.size >(uintptr_t) alignedAddress) {
			// Section shares page with previous
			if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
			}
			else {
				sectionData.characteristics |= section->Characteristics;
			}
			sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t)sectionSize)) - (uintptr_t)sectionData.address;
			continue;
		}

		if (!FinalizeSection(mMemory, &sectionData,header)) {
			return FALSE;
		}
		sectionData.address = sectionAddress;
		sectionData.alignedAddress = alignedAddress;
		sectionData.size = sectionSize;
		sectionData.characteristics = section->Characteristics;
	}
	sectionData.last = TRUE;
	if (!FinalizeSection(mMemory, &sectionData,header)) {
		return FALSE;
	}
	return TRUE;
}




static BOOL
FinalizeSection(PMemoryModule module, PSECTIONFINALIZEDATA sectionData,PIMAGE_NT_HEADERS header) {
	DWORD protect, oldProtect;
	BOOL executable;
	BOOL readable;
	BOOL writeable;

	if (sectionData->size == 0) {
		return TRUE;
	}
	//IMAGE_SCN_MEM_DISCARDABLE:可以根据需要丢弃，不再被使用，可以安全释放掉
	if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
		// section is not needed any more and can safely be freed
		if (sectionData->address == sectionData->alignedAddress &&
			(sectionData->last ||
				header->OptionalHeader.SectionAlignment == module->sysInfo.dwPageSize ||
				(sectionData->size % module->sysInfo.dwPageSize) == 0)
			) {
			// Only allowed to decommit whole pages
			VirtualFree(sectionData->address, sectionData->size, MEM_DECOMMIT, NULL);
			//module->free(sectionData->address, sectionData->size, MEM_DECOMMIT, module->userdata);
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

	// change memory access flags
	//修改区段访问权限
	if (VirtualProtect(sectionData->address, sectionData->size, protect, &oldProtect) == 0) {
		return FALSE;
	}

	return TRUE;
}