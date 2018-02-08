#include "stdafx.h"

int main()
{
	cout << "Process Hollowing" << endl;
	LPSTR lpCommandLine = (LPSTR)"svchost";

#ifdef _WIN64
	LPSTR lpSourceFile = (LPSTR)"D:\\users\\sudo\\Documents\\GitHub\\ProcessInjection\\x64\\Debug\\EXEPayload.exe";
#else
	LPSTR lpSourceFile = (LPSTR)"D:\\users\\sudo\\Documents\\GitHub\\ProcessInjection\\Debug\\EXEPayload.exe";
#endif // _WIN64

	HANDLE hProcess = CreateHollowedProcess(lpCommandLine, lpSourceFile);
	system("pause");

	if (hProcess) 
	{	
		TerminateProcess(hProcess, 4);
		WaitForSingleObject(hProcess, 0);
	}
	return 0;
}