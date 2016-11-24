#include "stdafx.h"

#include <iostream>
#include <string>
#include <cstring>
#include <fstream>

#include <easyhook.h>

using namespace std;

int main(int argc, _TCHAR* argv[]) {
	string username;

	ifstream usernameFile("username.conf");

	// We try to open the file
	if (usernameFile.is_open()) {
		// We read only the first line
		usernameFile >> username;
		usernameFile.close();
	}
	
	// If we cannot open the file or if it's empty, we stop here
	if (username.length() == 0) {
		printf("Please create the username.conf file");
		return -1;
	}

	// We must build a string like "HOSTNAME\USERNAME". The UTN Manager cuts the string and keeps only the username part
	username = "HOST\\" + username;

	// We initialize the structures to handle the start of the UTN Manager
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	wchar_t softwareExe[] = L"utnmanager.exe";
	// We start the UTN Manager Process in the suspended state because the software calls directly the syscall to get the current username
	if (!CreateProcess(NULL,				  // No module name (use command line)
					   softwareExe,     // The UTN Manager software
				       NULL,                  // Process handle not inheritable
					   NULL,                  // Thread handle not inheritable
					   FALSE,                 // Set handle inheritance to FALSE
					   CREATE_SUSPENDED,      // Create in suspended state
					   NULL,                  // Use parent's environment block
					   NULL,                  // Use parent's starting directory 
					   &si,                   // Pointer to STARTUPINFO structure
					   &pi)                   // Pointer to PROCESS_INFORMATION structure
		) {
		printf("CreateProcess failed (%d).\n", GetLastError());
		return -1;
	}

	// The process ID
	DWORD processId = pi.dwProcessId;

	// The DLL which must be injected
	WCHAR* dllToInject = L"H:\\null\\Documents\\Visual Studio 2015\\Projects\\SEHUTNManager-Usernamechanger\\Debug\\UTNManagerHook.dll";
	wprintf(L"Attempting to inject: %s\n\n", dllToInject);

	// Inject dllToInject into the target process Id, passing the username as the pass through data.
	NTSTATUS nt = RhInjectLibrary(processId,                               // The process to inject into
								  0,                                       // ThreadId to wake up upon injection
								  EASYHOOK_INJECT_DEFAULT,
								  dllToInject,                             // 32-bit
								  NULL,		                               // 64-bit not provided
								  (PVOID)username.c_str(),                 // Data to send to injected DLL entry point -> the username as char*
								  username.length() * sizeof(const char)); // Size of data to send
	
	if(nt != 0)	{ // Error
		printf("RhInjectLibrary failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << endl;

		return -1;
	} else 	{ // Success
		std::wcout << L"Library injected successfully.\n";

		// We resume the suspended thread
		ResumeThread(pi.hThread);

		// Wait until child process exits.
		WaitForSingleObject(pi.hProcess, INFINITE);

		// Close process and thread handles. 
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	return 0;
}