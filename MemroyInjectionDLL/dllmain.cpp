// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include <winsock.h>
#pragma comment(lib,"Ws2_32.lib")
#define MAX_MSG_LEN 1500
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
void __stdcall Connect()
{
	while (1)
	{
		TryConnect();
		Sleep(5000);
	}


}
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
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		std::cout << "DLL_PROCESS_ATTACH" << std::endl;
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)inj, NULL, 0, &dwThreadId);
		std::cout << dwThreadId << std::endl;
		break;
	case DLL_THREAD_ATTACH:
		std::cout << "DLL_THREAD_ATTACH" << std::endl;
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

