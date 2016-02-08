#ifndef __UTILS_H__
#define __UTILS_H__

#include "JuceHeader.h"
#include <fcntl.h>
#include <io.h>
#include"nt_ddk.h"

namespace Utils
{
	static BOOL IsElevated()
	{
		BOOL fRet = false;
		HANDLE hToken = NULL;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			TOKEN_ELEVATION Elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
				fRet = Elevation.TokenIsElevated;
		}
		if (hToken)
			CloseHandle(hToken);
		return fRet;
	}

	static void CreateDebugConsole(LPCSTR lPConsoleTitle)
	{
		HANDLE lStdHandle = 0;
		int hConHandle = 0;
		FILE *fp = 0;
		AllocConsole();
		lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
		hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
		SetConsoleTitleA(lPConsoleTitle);
		SetConsoleTextAttribute(lStdHandle, FOREGROUND_RED | FOREGROUND_BLUE | BACKGROUND_RED | BACKGROUND_BLUE | BACKGROUND_GREEN);
		fp = _fdopen(hConHandle, "w");
		*stdout = *fp;
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	static BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpPrivilege, BOOL bEnablePrivilege)
	{
		TOKEN_PRIVILEGES    tkp = { 0 };
		LUID                luid = { 0 };
		TOKEN_PRIVILEGES    tkpPrevious = { 0 };
		DWORD              cbPrevious = 0;

		//
		if (!LookupPrivilegeValue(NULL, lpPrivilege, &luid))
			return FALSE;
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = luid;
		tkp.Privileges[0].Attributes = 0;
		cbPrevious = sizeof(TOKEN_PRIVILEGES);
		AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), &tkpPrevious, &cbPrevious);
		if (GetLastError() != ERROR_SUCCESS)
			return FALSE;

		tkpPrevious.PrivilegeCount = 1;
		tkpPrevious.Privileges[0].Luid = luid;
		if (bEnablePrivilege)
			tkpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
		else
			tkpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tkpPrevious.Privileges[0].Attributes);
		AdjustTokenPrivileges(hToken, FALSE, &tkpPrevious, cbPrevious, NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS)
			return FALSE;

		return TRUE;
	}

	static BOOL SetDebugPrivilege(BOOL bEnable)
	{
		HANDLE hToken = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			return FALSE;
		// Enable/Disable Debug Privilege
		if (!SetPrivilege(hToken, SE_DEBUG_NAME, bEnable))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
	}

	static BOOL DoesDirectoryExist(const char* path)
	{
		DWORD dwAttributes = GetFileAttributes(path);
		if (dwAttributes == INVALID_FILE_ATTRIBUTES)
			return false;
		return (dwAttributes & FILE_ATTRIBUTE_DIRECTORY);
	}

	static void CreateDirectoryIfNeeded(const char* path)
	{
		if (!DoesDirectoryExist(path))
		{
			CreateDirectory(path, NULL);
		}
	}

	static HMODULE getLocalModuleHandle(const char* moduleName)
	{
		void* dwModuleHandle = 0;

		_TEB* teb = (_TEB*)NtCurrentTeb();
		_PEB* peb = (_PEB*)teb->ProcessEnvironmentBlock;
		PPEB_LDR_DATA ldrData = peb->Ldr;
		PLDR_DATA_ENTRY cursor = (PLDR_DATA_ENTRY)ldrData->InInitializationOrderModuleList.Flink;

		while (cursor->BaseAddress)  
		{
			#ifdef _DEBUG
			printf("Module [%S] loaded at [%p] with entrypoint at [%p]\n", cursor->BaseDllName.Buffer, cursor->BaseAddress, cursor->EntryPoint);
			#endif
			char strBaseDllName[MAX_PATH] = { 0 };
			size_t bytesCopied = 0;
			wcstombs_s(&bytesCopied, strBaseDllName, cursor->BaseDllName.Buffer, MAX_PATH);
			if (_stricmp(strBaseDllName, moduleName) == 0) {
				dwModuleHandle = cursor->BaseAddress;
				break;
			}
			cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
		}
		return (HMODULE)dwModuleHandle;
	}

	static void* getProcAddress(HMODULE module, const char *proc_name)
	{
		char *modb = (char *)module;

		IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)modb;
		IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)(modb + dos_header->e_lfanew);

		IMAGE_OPTIONAL_HEADER *opt_header = &nt_headers->OptionalHeader;
		IMAGE_DATA_DIRECTORY *exp_entry = (IMAGE_DATA_DIRECTORY *)(&opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		IMAGE_EXPORT_DIRECTORY *exp_dir = (IMAGE_EXPORT_DIRECTORY *)(modb + exp_entry->VirtualAddress);

		DWORD* func_table = (DWORD*)(modb + exp_dir->AddressOfFunctions);
		WORD* ord_table = (WORD *)(modb + exp_dir->AddressOfNameOrdinals);
		DWORD* name_table = (DWORD*)(modb + exp_dir->AddressOfNames);

		void *address = NULL;
		DWORD i;

		/* is ordinal? */
		if (((ULONG_PTR)proc_name >> 16) == 0)
		{
			WORD ordinal = LOWORD(proc_name);
			ULONG_PTR ord_base = exp_dir->Base;
			/* is valid ordinal? */
			if (ordinal < ord_base || ordinal > ord_base + exp_dir->NumberOfFunctions)
				return NULL;

			/* taking ordinal base into consideration */
			address = (void*)(modb + func_table[ordinal - ord_base]);
		}
		else
		{
			/* import by name */
			for (i = 0; i < exp_dir->NumberOfNames; i++)
			{
				/* name table pointers are rvas */
				char* procEntryName = (char*)((DWORD_PTR)modb + name_table[i]);
				if (_stricmp(proc_name, procEntryName) == 0)
				{
					address = (void*)(modb + func_table[ord_table[i]]);
					break;
				}
			}
		}
		/* is forwarded? */
		if ((char *)address >= (char*)exp_dir && (char*)address < (char*)exp_dir + exp_entry->Size)
		{
			char *dll_name, *func_name;
			HMODULE frwd_module;
			dll_name = _strdup((char*)address);
			if (!dll_name)
				return NULL;
			address = NULL;
			func_name = strchr(dll_name, '.');
			*func_name++ = 0;

			/* is already loaded? */
			frwd_module = (HMODULE)getLocalModuleHandle(dll_name);
			//if (!frwd_module)
			//frwd_module = LoadLibrary(dll_name);
			if (frwd_module)
				address = getProcAddress(frwd_module, func_name);

			free(dll_name);
		}
		return address;
	}

};

#endif