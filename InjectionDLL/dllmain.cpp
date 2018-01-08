// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "InjectionDLL.h"
#include <iostream>
#include <thread>
void WINAPI inj()
{
	Connect();
	return;
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	HANDLE hThread = NULL;
	DWORD dwThreadId;
	//Ping();
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			std::cout << "DLL_PROCESS_ATTACH" << std::endl;
			hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)inj, NULL, 0, &dwThreadId);
			//WaitForSingleObject(hThread, INFINITE);
			break;
		case DLL_THREAD_ATTACH:
		//Ping();
			std::cout << "DLL_THREAD_ATTACH" << std::endl;
			
			break;
		case DLL_THREAD_DETACH:
			std::cout << "DLL_THREAD_DETACH" << std::endl;
			break;
		case DLL_PROCESS_DETACH:
			std::cout << "DLL_PROCESS_DETACH" << std::endl;
			if (hThread != NULL)
			{
				CloseHandle(hThread);
			}
			break;
	}
//	Ping();
	return TRUE;
}



