// ReflectiveDLLInjection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string.h>
#include "LoadRemoteLibraryR.h"
using namespace std;

#define BreakForError(reason){cout << reason << endl; break;}

DWORD GetProcessIdByName(LPCTSTR processName)
{
	DWORD dwPID;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		cout << "Take SnapShot Failed!" << endl;
		return 0;
	}
	else
	{
		cout << "Take SnapShot Success!" << endl;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapShot, &pe))
	{
		cout << "Failed To Get The Information of System!" << endl;
		return 0;
	}
	else
	{
		cout << "Get the Information of System Success!" << endl;
	}

	while (Process32Next(hSnapShot, &pe))
	{

		if (!strcmp((const char *)processName, (const char *)pe.szExeFile))
			return pe.th32ProcessID;

	}
	return 0;
}


BOOL PrivilegeEscalation()
{

	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		return FALSE;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;

	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		return FALSE;
	CloseHandle(hToken);
	return TRUE;
}

int main()
{
	do
	{

		LPCTSTR processName = L"notepad.exe";
		DWORD dwPid = GetProcessIdByName(processName);
		if (dwPid == 0)
			BreakForError("Failed to Get the notepad's PID.");
		cout << "The PID of Notepad.exe is :" << dwPid << endl;

		LPCSTR injectionDll = "f:\\reflective_dll.x64.dll";
		//Get the Handle of the DLL file.
		HANDLE hFile = CreateFileA(injectionDll, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			BreakForError("Failed to open the DLL file.");

		//Get the DLL file size.
		DWORD dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
			BreakForError("Failed to get the DLL file size.");

		//在当前进程分配缓冲区
		LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
		if (!lpBuffer)
			BreakForError("Failed to alloc a buffer.");
		//Read the DLL file.
		DWORD dwBytesRead = 0;
		if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == false)
			BreakForError("Failed to read the DLL file");
		if (!PrivilegeEscalation())
			BreakForError("Failed to Escalate Privilege.");

		//Open target process
		HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());//dwPid);
		if (!hTargetProcess)
			BreakForError("Failed to Open the Target Process.");

		//Inject into target process
		HANDLE hMoudle = LoadRemoteLibraryR(hTargetProcess, lpBuffer, dwLength, NULL);

	} while (0);
	system("pause");
	return 0;
}

