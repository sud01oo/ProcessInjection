// DLLTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "InjectionDLL.h"
#include <Windows.h>
int main()
{
	//Ping();
	HMODULE H = LoadLibraryA("InjectionDLL.dll");

	//FARPROC ping = GetProcAddress(H, "Ping");
//	ping();
	while (1);
    return 0;
}

