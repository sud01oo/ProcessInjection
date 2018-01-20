// ReflectiveDemo.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include "ReflectiveLoader.h"
using namespace std;

int main()
{
	do
	{
		//已经编译出的dll，在实现LoadLibraryA函数阶段，可以是任意DLL
		char *dllFile = "F:\\ReflectiveDLLInjection\\x64\\Debug\\reflective_dll.dll";
		HANDLE hFile = CreateFileA(dllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			cout << "File Path is Wrong!" << endl;
			break;
		}
		else
		{
			cout << "Get File Success." << endl;
		}
		DWORD dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
		{
			cout << "Failed to get the Dll file size." << endl;
			break;
		}
		else
		{
			cout << "File size is :" << dwLength << endl;
		}
		LPVOID hBaseAddress = VirtualAlloc(NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!hBaseAddress)
		{
			cout << "Failed to Alloc Memory." << endl;
			break;
		}
		else
		{
			cout << "BaseAddress is :" << hBaseAddress << endl;
		}
		DWORD dwBytesRead;
		if (ReadFile(hFile, hBaseAddress, dwLength, &dwBytesRead, NULL) == false)
			cout << "Failed to Read File!" << endl;
		ReflectiveLoader((ULONG_PTR)hBaseAddress);

	} while (0);
	system("parse");
	return 0;
}

