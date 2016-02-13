#ifndef __UTILS_H__
#define __UTILS_H__

#include "JuceHeader.h"
#include <fcntl.h>
#include <io.h>
#include"nt_ddk.h"

namespace Utils
{
	// forward declarations
	static void* GetProcAddress(HMODULE module, const char *proc_name);
	static HMODULE GetLocalModuleHandle(const char* moduleName);
	static HMODULE GetRemoteModuleHandle(const char* moduleName);
	static void* GetRemoteProcAddress(HMODULE module, const char *proc_name);

	// Align value
	static inline size_t Align(size_t val, size_t alignment)
	{
		return (val % alignment == 0) ? val : (val / alignment + 1) * alignment;
	}

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

	static std::wstring StripPath(const std::wstring& path)
	{
		if (path.empty())
			return path;

		auto idx = path.rfind(L'\\');
		if (idx == path.npos)
			idx = path.rfind(L'/');

		if (idx != path.npos)
			return path.substr(idx + 1);
		else
			return path;
	}

	static bool FileExists(const std::wstring& path)
	{
		return (GetFileAttributesW(path.c_str()) != 0xFFFFFFFF);
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
			CreateDirectory(path, NULL);
	}

	static std::wstring GetProcessDirectory(HANDLE hProcess)
	{
		void* dwModuleHandle = 0;

		PPROCESS_BASIC_INFORMATION pbi = NULL;
		PEB peb;
		PEB_LDR_DATA peb_ldr;

		// Try to allocate buffer 
		HANDLE	hHeap = GetProcessHeap();
		DWORD dwSize = sizeof(PROCESS_BASIC_INFORMATION);
		pbi = (PPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSize);

		ULONG dwSizeNeeded = 0;

		static tNTQIP fnNtQueryInformationProcess = (tNTQIP)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

		NTSTATUS dwStatus = fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, dwSize, &dwSizeNeeded);
		if (dwStatus >= 0 && dwSize < dwSizeNeeded)
		{
			if (pbi)
				HeapFree(hHeap, 0, pbi);

			pbi = (PPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSizeNeeded);
			if (!pbi)
			{
				#ifdef _DEBUG
				printf("Couldn't allocate heap buffer!\n");
				#endif
				return NULL;
			}

			dwStatus = fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, dwSizeNeeded, &dwSizeNeeded);
		}

		// Did we successfully get basic info on process
		if (dwStatus >= 0)
		{
			// Read Process Environment Block (PEB)
			if (pbi->PebBaseAddress)
			{
				SIZE_T dwBytesRead = 0;
				if (ReadProcessMemory(hProcess, pbi->PebBaseAddress, &peb, sizeof(peb), &dwBytesRead))
				{
					dwBytesRead = 0;
					if (ReadProcessMemory(hProcess, peb.Ldr, &peb_ldr, sizeof(peb_ldr), &dwBytesRead))
					{
						LIST_ENTRY *pLdrListHead = (LIST_ENTRY *)peb_ldr.InLoadOrderModuleList.Flink;
						LIST_ENTRY *pLdrCurrentNode = peb_ldr.InLoadOrderModuleList.Flink;

						LDR_DATA_TABLE_ENTRY lstEntry = { 0 };
						dwBytesRead = 0;
						if (!ReadProcessMemory(hProcess, (void*)pLdrCurrentNode, &lstEntry, sizeof(LDR_DATA_TABLE_ENTRY), &dwBytesRead))
						{
							if (pbi)
								HeapFree(hHeap, 0, pbi);
							return NULL;
						}

						pLdrCurrentNode = lstEntry.InLoadOrderLinks.Flink;

						wchar_t wcsFullDllName[MAX_PATH] = { 0 };
						if (lstEntry.BaseDllName.Length > 0)
						{
							dwBytesRead = 0;
							if (ReadProcessMemory(hProcess, (LPCVOID)lstEntry.FullDllName.Buffer, &wcsFullDllName, lstEntry.FullDllName.Length, &dwBytesRead))
							{
								wchar_t* pathEnd = 0;
								pathEnd = wcsrchr(wcsFullDllName, L'\\');
								if (!pathEnd)
									pathEnd = wcsrchr(wcsFullDllName, L'/');

								*pathEnd++ = L'\0';

								return std::wstring(wcsFullDllName);
							}
						}
					} // Get Ldr
				} // Read PEB 
			} // Check for PEB
		}

		if (pbi)
			HeapFree(hHeap, 0, pbi);

		return std::wstring();
	}

	static LONG GetProcessorArchitecture()
	{
		static LONG volatile nProcessorArchitecture = -1;
		if (nProcessorArchitecture == -1)
		{
			SYSTEM_PROCESSOR_INFORMATION sProcInfo;
			NTSTATUS nNtStatus;

			tRtlGetNativeSystemInformation fnRtlGetNativeSystemInformation = (tRtlGetNativeSystemInformation)Utils::GetProcAddress((HMODULE)Utils::GetLocalModuleHandle("ntdll.dll"), "RtlGetNativeSystemInformation");
			nNtStatus = fnRtlGetNativeSystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo, sizeof(sProcInfo), NULL);
			if (nNtStatus == STATUS_NOT_IMPLEMENTED)
			{
				tNTQSI fnQuerySystemInformation = (tNTQSI)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
				nNtStatus = fnQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo, sizeof(sProcInfo), NULL);
			}
			if (NT_SUCCESS(nNtStatus))
				_InterlockedExchange(&nProcessorArchitecture, (LONG)(sProcInfo.ProcessorArchitecture));
		}
		return nProcessorArchitecture;
	}

	static HMODULE GetLocalModuleHandle(const char* moduleName)
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

	static void* GetProcAddress(HMODULE module, const char *proc_name)
	{
		char *modb = (char *)module;

		IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)modb;
		IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((size_t)modb + dos_header->e_lfanew);

		IMAGE_OPTIONAL_HEADER *opt_header = &nt_headers->OptionalHeader;
		IMAGE_DATA_DIRECTORY *exp_entry = (IMAGE_DATA_DIRECTORY *)(&opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		IMAGE_EXPORT_DIRECTORY *exp_dir = (IMAGE_EXPORT_DIRECTORY *)((size_t)modb + exp_entry->VirtualAddress);

		DWORD* func_table = (DWORD*)((size_t)modb + exp_dir->AddressOfFunctions);
		WORD* ord_table = (WORD *)((size_t)modb + exp_dir->AddressOfNameOrdinals);
		DWORD* name_table = (DWORD*)((size_t)modb + exp_dir->AddressOfNames);

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
			address = (void*)((size_t)modb + func_table[ordinal - ord_base]);
		}
		else
		{
			/* import by name */
			for (i = 0; i < exp_dir->NumberOfNames; i++)
			{
				/* name table pointers are rvas */
				char* procEntryName = (char*)((size_t)modb + name_table[i]);
				if (_stricmp(proc_name, procEntryName) == 0)
				{
					address = (void*)((size_t)modb + func_table[ord_table[i]]);
					break;
				}
			}
		}
		/* is forwarded? */
		if ((char *)address >= (char*)exp_dir && (char*)address < (char*)exp_dir + exp_entry->Size)
		{
			HMODULE frwd_module = 0;

			char* dll_name = _strdup((char*)address);
			if (!dll_name)
				return NULL;
			char* func_name = strchr(dll_name, '.');
			*func_name++ = 0;

			address = NULL;

			char dllName[256];
			strcpy_s(dllName, dll_name);
			strcat_s(dllName, strlen(dll_name) + 4 + 1, ".dll");

			/* is already loaded? */
			frwd_module = (HMODULE)Utils::GetLocalModuleHandle(dllName);
			if (!frwd_module)
				frwd_module = LoadLibraryA(dllName);
			if (!frwd_module)
			{
				MessageBox(0, "GetProcAddress failed to load module using GetModuleHandle and LoadLibrary!", "injectora", MB_ICONERROR);
				return NULL;
			}

			bool forwardByOrd = strchr(func_name, '#') == 0 ? false : true;
			if (forwardByOrd) // forwarded by ordinal
			{
				WORD func_ord = atoi(func_name + 1);
				address = Utils::GetProcAddress(frwd_module, (const char*)func_ord);
			}
			else
			{
				address = Utils::GetProcAddress(frwd_module, func_name);
			}

			free(dll_name);
		}
		return address;
	}

	static HANDLE NtCreateThreadEx(HANDLE hProcess, LPVOID lpRemoteThreadStart, LPVOID lpParam, DWORD* threadId)
	{
		tNtCreateThreadEx NtCreateThreadEx = (tNtCreateThreadEx)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "NtCreateThreadEx");
		if (NtCreateThreadEx == NULL)
			return NULL;

		PS_ATTRIBUTE_LIST attrList;
		ZeroMemory(&attrList, sizeof(PS_ATTRIBUTE_LIST));
		CLIENT_ID cid;
		ZeroMemory(&cid, sizeof(CLIENT_ID));
		OBJECT_ATTRIBUTES64 thrdAttr;
		InitializeObjectAttributes64(&thrdAttr, NULL, 0, NULL, NULL);

		attrList.Attributes[0].Attribute = ProcThreadAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE);
		attrList.Attributes[0].Size = sizeof(CLIENT_ID);
		attrList.Attributes[0].ValuePtr = (ULONG_PTR*)&cid;

		attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);

		HANDLE hRemoteThread = NULL;
		HRESULT hRes = 0;

		if (!NT_SUCCESS(NtCreateThreadEx(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess, lpRemoteThreadStart, lpParam, 0, 0, 0x1000, 0x100000, &attrList)))
			return NULL;

		if (threadId)
			*threadId = (DWORD)cid.UniqueThread;

		return hRemoteThread;
	}

};

#endif