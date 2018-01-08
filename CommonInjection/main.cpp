#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
using namespace std;

void PrivilegeEscalation();
HANDLE GetThePidOfTargetProcess();
BOOL DoInjection(char *InjectionDllPath, HANDLE injectionProcessHandle);
int main()
{
	char InjectionDllPath[] = { "D:\\InjectionDLL.dll" };
	//Get the pid of notepad.exe which is to be injected.
	HANDLE injectionProcessHandle = GetThePidOfTargetProcess();
	if (injectionProcessHandle == 0)
	{
	
		cout << "Can't Get The PID" << endl;
	}
	//Privilege Escalation
	PrivilegeEscalation();
	if (DoInjection(InjectionDllPath, injectionProcessHandle))
	{
		cout << "Injection Success" << endl;
	}
	else
	{
		cout << "Inject Failed!" << endl;
	}
	system("pause");
}

HANDLE GetThePidOfTargetProcess()
{
	
	//Get the pid of the process which to be injected.
	HWND injectionProcessHwnd = FindWindowA(0, "Untitled - Notepad");
	DWORD dwInjectionProcessID;
	GetWindowThreadProcessId(injectionProcessHwnd, &dwInjectionProcessID);
	cout << "Notepad's pid -> " << dwInjectionProcessID << endl;
	HANDLE injectionProcessHandle = ::OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD, 0, dwInjectionProcessID);//dwInjectionProcessID);
	return injectionProcessHandle;
}

void PrivilegeEscalation()
{

	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}
BOOL DoInjection(char *InjectionDllPath,HANDLE injectionProcessHandle)
{
	DWORD injBufSize = lstrlen((LPCWSTR)InjectionDllPath) + 1;
	LPVOID AllocAddr = VirtualAllocEx(injectionProcessHandle, NULL, injBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (AllocAddr == 0)
	{
		cout << "Alloc memory failed!" << endl;
	}
	else
		cout << "Alloc Memory success!" << endl;
	WriteProcessMemory(injectionProcessHandle, AllocAddr, (void*)InjectionDllPath, injBufSize, NULL);
	DWORD ER = GetLastError();
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	cout << "The LoadLibrary's Address is:" << pfnStartAddr << endl;
	HANDLE hRemoteThread;
	if ((hRemoteThread = CreateRemoteThread(injectionProcessHandle, NULL, 0, pfnStartAddr, AllocAddr, 0, NULL)) == NULL)
	{
		ER = GetLastError();
		cout << "Create Remote Thread Failed!" << endl;
		return FALSE;
	}
	else
	{
		cout << "Create Remote Thread Success!" << endl;
		return TRUE;
	}
}



