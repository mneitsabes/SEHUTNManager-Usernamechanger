#define SECURITY_WIN32 1

#include <easyhook.h>

#include <security.h>
#include <string>
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <cwchar>

using namespace std;

wstring username;

/**
 * GetUserNameExW() override.
 * 
 * This function put in :
 *   - lpNameBuffer : the value of the global username variable 
 *   - lpnSize : the length of the username
 */
BOOL WINAPI myGetUserNameExW(EXTENDED_NAME_FORMAT nameFormat, LPTSTR lpNameBuffer, PULONG lpnSize)
{
	memcpy(lpNameBuffer, username.c_str(), username.length() * sizeof(LPTSTR));
	*lpnSize = username.length();

	return TRUE;
}

/**
 * EasyHook will be looking for this export to support DLL injection
 */
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);


void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	// The username is provided as char* through inRemoteInfo->UserData and the length through inRemoteInfo->UserDataSize
	
	// Transform the char* as std::string
	string usernameAsString(reinterpret_cast<const char *>(inRemoteInfo->UserData));

	// Convert the std::string to wchar_t*
	wchar_t * wcstring = new wchar_t[inRemoteInfo->UserDataSize + 1];

	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstring, inRemoteInfo->UserDataSize + 1, reinterpret_cast<const char *>(inRemoteInfo->UserData), _TRUNCATE);

	// Create the wstring from the wchar_t*
	username = wstring(wcstring, convertedChars);

	// Free the alloced memory
	delete wcstring;

	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

	// Install the hook
	NTSTATUS result = LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("Secur32.dll")), "GetUserNameExW"), // Address of GetUserNameExW
									myGetUserNameExW, // The custom function which will be used for hooking
									NULL,
									&hHook);

	// If the hooking failed, we create a debug log file
	if(FAILED(result)) {
		ofstream debugFile;
		debugFile.open("hook_debug.log");

		debugFile << "Hooking failed" << endl;
		debugFile << "Injected by process ID : " << inRemoteInfo->HostPID << endl;
		debugFile << "Passed in data size : " << inRemoteInfo->UserDataSize << endl;
		debugFile << "Address of GetUserNameExW : " << GetProcAddress(GetModuleHandle(TEXT("Secur32.dll")), "GetUserNameExW") << endl;
		debugFile << "Error message : " << RtlGetLastErrorString() << endl;

		debugFile.close();
	}

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &hHook);

	return;
}
