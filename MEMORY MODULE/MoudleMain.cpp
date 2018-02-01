#include <iostream>
#include "Loader.h"
using namespace std;
/*
在反射式进程注入中，我们已经实现了一次对DLL的解析，但在内存中存在大片的RWX区域，
在GitHub上的名为Memory Mouldle项目中，发现了一种可以将内存属性设置为与正常加载
较为相似的方法，这个项目就是对这种方法的学习。

*/
int main()
{
	do
	{
		//已经编译出的dll，在实现LoadLibraryA函数阶段，可以是任意DLL
		char *dllFile = "C:\\Users\\sudo\\Desktop\\ReflectiveDLLPEForm\\x64\\Debug\\ReflectiveDLL.dll";
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
		//dll在内存中的地址（未加载）
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
		Loader((ULONG_PTR)hBaseAddress);

	} while (0);
	system("parse");
	return 0;
}