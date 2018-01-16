// ReflectiveDLL.cpp : Defines the exported functions for the DLL application.
//
#include "stdafx.h"
#include "ReflectiveDLL.h"

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }
extern "C" _declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	USHORT usCounter;

	//内存中镜像的初始位置
	ULONG_PTR uiLibraryAddress;
	//内核基地址，之后镜像会重新加载到基地址
	ULONG_PTR uiBaseAddress;
	//用来处理内核导出表的变量
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;


	//加载镜像所使用的变量
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;


	// 第一步：计算镜像当前基地址

	// we will start searching backwards from our callers return address.
	uiLibraryAddress = caller();
	//std::cout << std::hex << uiLibraryAddress << std::endl;
	return 0;
}
