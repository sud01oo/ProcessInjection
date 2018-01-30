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
		//这里依旧是任意DLL，我们要实现的功能就是从内存里把DLL加载了，功能依旧是解析DLL
		char *dllFile = "F:\\ReflectiveDLLInjection\\x64\\Debug\\reflective_dll.dll";
		HANDLE hFile = CreateFileA(dllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			cout << "File Path is Wrong!" << endl;
			break;
		}
		else
		{
			cout << "Get File Success!" << endl;
		}
		DWORD dwLength = GetFileSize(hFile, NULL);
		if(dwLength == INVALID_FILE_SIZE ||)
	}
}