#include "main.h"
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	MessageBoxA(NULL, "test", "tt", 0);
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
