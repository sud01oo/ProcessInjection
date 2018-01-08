// InjectionDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "InjectionDLL.h"
#include <winsock.h>
#pragma comment(lib,"Ws2_32.lib")
#define MAX_MSG_LEN 1500
void TryConnect();
void __stdcall Connect()
{
	while (1)
	{
		TryConnect();
		Sleep(5000);
	}

	
}

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

