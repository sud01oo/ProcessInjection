// dllmain.cpp : Defines the entry point for the DLL application.
#include "ReflectiveLoader.h"
#include <winsock.h>
#pragma comment(lib,"Ws2_32.lib")
#define DLL_QUERY_HMODULE		6
extern HINSTANCE hAppInstance;
DWORD dwThreadId;
void TryConnect()
{
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0)
	{
		return;
	}
	SOCKET m_socket = socket(AF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN SocketSendIn;
	SocketSendIn.sin_family = AF_INET;
	SocketSendIn.sin_addr.S_un.S_addr = inet_addr("114.114.114.114");
	SocketSendIn.sin_port = htons(53);
	connect(m_socket, (SOCKADDR*)&SocketSendIn, sizeof(SOCKADDR));
	closesocket(m_socket);
	WSACleanup();
}
void WINAPI inj()
{
	while (1)
	{
		TryConnect();
		Sleep(5000);
	}
}
BOOL APIENTRY DllMain( HINSTANCE hinstDLL,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	BOOL bReturnValue = TRUE;
	switch (ul_reason_for_call)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)inj, NULL, 0, &dwThreadId);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

