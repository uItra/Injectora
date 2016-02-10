#include "CRemoteLoader.h"

#include <Tlhelp32.h>
#include <DbgHelp.h>

#pragma comment (lib, "DbgHelp.lib")

#ifdef UNICODE
#undef UNICODE
#endif

#define MakePtr(cast, ptr, addValue) (cast)((DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define MakeDelta(cast, x, y) (cast)((DWORD_PTR)(x) - (DWORD_PTR)(y))

// ######################
// ## Public functions ##
// ######################
void CRemoteLoader::SetProcess(HANDLE hProcess)
{
	HMODULE hNtDll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	fnNTQIP = (tNTQIP)Utils::GetProcAddress(hNtDll, "NtQueryInformationProcess");
	fnNTQSI = (tNTQSI)Utils::GetProcAddress(hNtDll, "NtQuerySystemInformation");

	m_hProcess = hProcess;
	m_bIs64bit = GetProcessPlatform() == 2 ? true : false;
}

HMODULE CRemoteLoader::LoadLibraryByPathA(LPCCH Path)
{
	WCHAR Module[MAX_PATH] = { 0 };
	size_t charsConverted;
	mbstowcs_s(&charsConverted, Module, Path, MAX_PATH);

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryByPathA] ( %S -> %s )", Module, Path);
	#endif

	return LoadLibraryByPathW(Module);
}

HMODULE CRemoteLoader::LoadLibraryByPathW(LPCWCH Path)
{
	if (Path == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] szString is NULL");
		#endif
		return NULL;
	}
	
	FARPROC RemoteLoadLibraryW = GetRemoteProcAddress("kernel32.dll", "LoadLibraryW");
	if (RemoteLoadLibraryW == NULL)
	{
		RemoteLoadLibraryW = (FARPROC)Utils::GetProcAddress(Utils::GetLocalModuleHandle("kernel32.dll"), "LoadLibraryW");
		if (RemoteLoadLibraryW == NULL)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadLibraryByPathW] LoadLibraryW Resolve Failure");
			#endif
			return NULL;
		}
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryByPathW] LoadLibraryW = 0x%X", RemoteLoadLibraryW);
	#endif

	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(size_t));
	
	PushUNICODEString(Path);
	if (m_bIs64bit)
		PushCall(CCONV_FASTCALL, RemoteLoadLibraryW);
	else
		PushCall(CCONV_STDCALL, RemoteLoadLibraryW);
	
	if (m_bIs64bit)
	{
		//mov ptr, rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);
	
		Epilogue64();
	}
	else
	{
		//mov ptr, eax
		AddByteToBuffer(0xA3);
		AddLongToBuffer((unsigned long)ReturnPointerValue);
	
		//xor eax, eax
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);
	
		//retn 4
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x04);
		AddByteToBuffer(0x00);
	}
	
	if (ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true) == false)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] ExecuteRemoteThreadBuffer failed");
		#endif
	
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
	
		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleByNameW] ExecuteRemoteThreadBuffer succeeded");
	#endif
	
	size_t RemoteModuleHandle = 0;
	if (ReadProcessMemory(m_hProcess, ReturnPointerValue, &RemoteModuleHandle, sizeof(HMODULE), NULL))
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
	}
	else
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
		if (RemoteModuleHandle == 0)
			RemoteModuleHandle = (size_t)GetRemoteModuleHandleW(Path);
	}

	return (HMODULE)RemoteModuleHandle;
}

HMODULE CRemoteLoader::LoadLibraryByPathIntoMemoryA(LPCCH Path, BOOL PEHeader)
{
	HMODULE hReturnValue = NULL;

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryByPathIntoMemoryA] %s", Path);
	#endif
	
	ModuleFile File = InitModuleFile(Path);
	if (File.IsValid() == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathIntoMemoryA] Failed to open file handle!");
		#endif

		MessageBox(0, "Failed to open DLL file!", "Injectora", MB_ICONERROR);

		return NULL;
	}

	hReturnValue = LoadLibraryFromMemory(File.Buffer, File.Size, PEHeader);
	if (FreeModuleFile(File) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathIntoMemoryA] Failed to free file handle...");
		#endif
	}

	return hReturnValue;
}

HMODULE CRemoteLoader::LoadLibraryByPathIntoMemoryW(LPCWCH Path, BOOL PEHeader)
{
	CHAR PathAnsi[MAX_PATH] = { 0 };

	size_t charsConverted;

	wcstombs_s(&charsConverted, PathAnsi, Path, MAX_PATH);
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryByPathIntoMemoryW]( %S -> %s )( 0x%X )", Path, PathAnsi, PEHeader);
	#endif

	return LoadLibraryByPathIntoMemoryA(PathAnsi, PEHeader);
}

HMODULE CRemoteLoader::LoadLibraryFromMemory(PVOID BaseAddress, DWORD SizeOfModule, BOOL PEHeader)
{
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] BaseAddress (0x%X) - SizeOfModule (0x%X)", BaseAddress, SizeOfModule);
	#endif

	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Invalid Image: No IMAGE_NT_HEADERS");
		#endif
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] SizeOfImage (0x%X)", ImageNtHeaders->OptionalHeader.SizeOfImage);
	#endif
	
	if (ImageNtHeaders->FileHeader.NumberOfSections == 0)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Invalid Image: No Sections");
		#endif
		return NULL;
	}

	if ((ImageNtHeaders->OptionalHeader.ImageBase % 4096) != 0)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Invalid Image: Not Page Aligned");
		#endif
		return NULL;
	}


	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size 
		&& ImageDirectoryEntryToData(BaseAddress, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR))
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] This method is not supported for Managed executables!");
		#endif

		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] No COM/CLR data found!");
	#endif

	// SizeOfImage NOT the same as module size MOTHERFUCKER
	// http://www.youtube.com/watch?v=pele5vptVgc
	void* AllocatedRemoteMemory = RemoteAllocateMemory(ImageNtHeaders->OptionalHeader.SizeOfImage);
	if (AllocatedRemoteMemory == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to allocate remote memory for module!");
		#endif
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Allocated remote module at [0x%X]!", AllocatedRemoteMemory);
	#endif
	
	printf("Processing Import Tables....\n");
	if (ProcessImportTable(BaseAddress, AllocatedRemoteMemory) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to fix imports!");
		#endif
		return NULL;
	}

	if (ProcessDelayedImportTable(BaseAddress, AllocatedRemoteMemory) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to fix delayed imports!");
		#endif
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Fixed Imports!");
	#endif

	if (ProcessRelocations(BaseAddress, AllocatedRemoteMemory) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to process relocations!");
		#endif
		RemoteFreeMemory(AllocatedRemoteMemory, SizeOfModule);
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Fixed Relocations!");
	#endif

	if (ProcessSections(BaseAddress, AllocatedRemoteMemory, PEHeader) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to process sections!");
		#endif
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Processed sections!");
	#endif
	
	if (ProcessTlsEntries(BaseAddress, AllocatedRemoteMemory) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadModuleFromMemory] ProcessTlsEntries Failed!");
		#endif
		// we can also choose to continue here, but we wont
		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleFromMemory] Processed Tls Entries!");
	#endif

	if (ImageNtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		FARPROC DllEntryPoint = MakePtr(FARPROC, AllocatedRemoteMemory, ImageNtHeaders->OptionalHeader.AddressOfEntryPoint);
		
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadModuleFromMemory] DllEntrypoint = 0x%X", DllEntryPoint);
		#endif

		if (CallEntryPoint(AllocatedRemoteMemory, DllEntryPoint) == false)
		{
		
		#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadModuleFromMemory] Failed to execute remote thread buffer");

		}
		else
		{
			DebugShout("[LoadModuleFromMemory] Executed the remote thread buffer successfully [0x%X]", DllEntryPoint);
		#endif

		}
	}
	#ifdef DEBUG_MESSAGES_ENABLED
	else
	{
		DebugShout("[LoadModuleFromMemory] AddressOfEntryPoint is NULL");
	}
	#endif

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleFromMemory] Returning Pointer (0x%X)", AllocatedRemoteMemory);
	#endif

	return (HMODULE)AllocatedRemoteMemory;
}

// Private functions
HMODULE CRemoteLoader::GetRemoteModuleHandleA(const char* Module)
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
	NTSTATUS dwStatus = fnNTQIP(m_hProcess, ProcessBasicInformation, pbi, dwSize, &dwSizeNeeded);
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

		dwStatus = fnNTQIP(m_hProcess, ProcessBasicInformation, pbi, dwSizeNeeded, &dwSizeNeeded);
	}

	// Did we successfully get basic info on process
	if (dwStatus >= 0)
	{
		// Read Process Environment Block (PEB)
		if (pbi->PebBaseAddress)
		{
			SIZE_T dwBytesRead = 0;
			if (ReadProcessMemory(m_hProcess, pbi->PebBaseAddress, &peb, sizeof(peb), &dwBytesRead))
			{
				dwBytesRead = 0;
				if (ReadProcessMemory(m_hProcess, peb.Ldr, &peb_ldr, sizeof(peb_ldr), &dwBytesRead))
				{
					LIST_ENTRY *pLdrListHead = (LIST_ENTRY *)peb_ldr.InLoadOrderModuleList.Flink;
					LIST_ENTRY *pLdrCurrentNode = peb_ldr.InLoadOrderModuleList.Flink;
					do
					{
						LDR_DATA_TABLE_ENTRY lstEntry = { 0 };
						dwBytesRead = 0;
						if (!ReadProcessMemory(m_hProcess, (void*)pLdrCurrentNode, &lstEntry, sizeof(LDR_DATA_TABLE_ENTRY), &dwBytesRead))
						{
							#ifdef _DEBUG
							char dbgOut[1024];
							sprintf_s(dbgOut, "CRemoteLoader[GetRemoteModuleHandleA] Could not read list entry from LDR list. Error = %X", GetLastError());
							MessageBox(0, dbgOut, "Injectora", MB_ICONERROR);
							#endif

							if (pbi)
								HeapFree(hHeap, 0, pbi);
							return NULL;
						}

						pLdrCurrentNode = lstEntry.InLoadOrderLinks.Flink;

						wchar_t wcsBaseDllName[MAX_PATH] = { 0 };
						char strBaseDllName[MAX_PATH] = { 0 };
						if (lstEntry.BaseDllName.Length > 0)
						{
							dwBytesRead = 0;
							if (ReadProcessMemory(m_hProcess, (LPCVOID)lstEntry.BaseDllName.Buffer, &wcsBaseDllName, lstEntry.BaseDllName.Length, &dwBytesRead))
							{
								size_t bytesCopied = 0;
								wcstombs_s(&bytesCopied, strBaseDllName, wcsBaseDllName, MAX_PATH);
							}
						}

						if (lstEntry.DllBase != nullptr && lstEntry.SizeOfImage != 0)
						{
							if (_stricmp(strBaseDllName, Module) == 0)
							{
								dwModuleHandle = lstEntry.DllBase;
								break;
							}
						}

					} while (pLdrListHead != pLdrCurrentNode);

				} // Get Ldr
			} // Read PEB 
		} // Check for PEB
	}

	if (pbi)
		HeapFree(hHeap, 0, pbi);

	return (HMODULE)dwModuleHandle;
}

HMODULE CRemoteLoader::GetRemoteModuleHandleW(LPCWCH Module)
{
	char ModuleAnsi[MAX_PATH] = { 0 };
	size_t charsConverted;
	wcstombs_s(&charsConverted, ModuleAnsi, Module, MAX_PATH);
	return GetRemoteModuleHandleA(ModuleAnsi);
}

FARPROC CRemoteLoader::GetRemoteProcAddress(HMODULE Module, LPCCH Function)
{
	if (!Module)
	{
		#ifdef _DEBUG
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
		#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl(Module, (const char*)Function);
}

FARPROC CRemoteLoader::GetRemoteProcAddress(LPCCH Module, LPCCH Function)
{
	HMODULE hMod = GetRemoteModuleHandleA(Module);
	if (!hMod)
		hMod = LoadLibraryByPathA(Module);
	if (!hMod)
	{
		#ifdef _DEBUG
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
		#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl(hMod, (const char*)Function);
}

FARPROC CRemoteLoader::GetRemoteProcAddress(HMODULE Module, SHORT Function)
{
	if (!Module)
	{
		#ifdef _DEBUG
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
		#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl(Module, (const char*)Function);
}

FARPROC CRemoteLoader::GetRemoteProcAddress(LPCCH Module, SHORT Function)
{
	HMODULE hMod = GetRemoteModuleHandleA(Module);
	if (!hMod)
		hMod = LoadLibraryByPathA(Module);
	if (!hMod)
	{
		#ifdef _DEBUG
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
		#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl(hMod, (const char*)Function);
}

void* CRemoteLoader::GetRemoteProcAddressImpl(HMODULE module, const char *proc_name)
{
	char *modb = (char*)module;

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
		frwd_module = (HMODULE)GetRemoteModuleHandleA(dllName);
		if (!frwd_module)
			frwd_module = LoadLibraryByPathA(dllName);
		if (!frwd_module)
		{
			printf("GetRemoteProcAddress failed to load module using GetRemoteModuleHandle and LoadLibrary!");
			return NULL;
		}

		bool forwardByOrd = strchr(func_name, '#') == 0 ? false : true;
		if (forwardByOrd) // forwarded by ordinal
		{
			WORD func_ord = atoi(func_name + 1);
			address = GetRemoteProcAddressImpl(frwd_module, (const char*)func_ord);
		}
		else
		{
			address = GetRemoteProcAddressImpl(frwd_module, func_name);
		}

		free(dll_name);
	}
	return address;
}

IMAGE_DOS_HEADER* CRemoteLoader::ToDos(PVOID BaseAddress)
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)(BaseAddress);
	if (!ImageDosHeader)
		return NULL;

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	return ImageDosHeader;
}

IMAGE_NT_HEADERS* CRemoteLoader::ToNts(PVOID BaseAddress)
{
	IMAGE_DOS_HEADER* ImageDosHeader = ToDos(BaseAddress);
	if (ImageDosHeader == 0)
		return 0;
	IMAGE_NT_HEADERS* ImageNtHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)BaseAddress + ImageDosHeader->e_lfanew);
	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	return ImageNtHeaders;
}

void* CRemoteLoader::RvaToPointer(ULONG RVA, PVOID BaseAddress)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == 0)
		return 0;
	return ::ImageRvaToVa(ImageNtHeaders, BaseAddress, RVA, 0);
}

PVOID CRemoteLoader::ImageDirectoryEntryToData(PVOID BaseAddress, USHORT DataDirectory)
{
	ULONG dummySize = 0;
	return ::ImageDirectoryEntryToData(BaseAddress, TRUE, DataDirectory, &dummySize);
}

BOOL CRemoteLoader::CallEntryPoint(void* BaseAddress, FARPROC Entrypoint)
{
	if (m_bIs64bit)
	{
		PushInt64((unsigned __int64)BaseAddress);
		PushInt64(DLL_PROCESS_ATTACH);
		PushInt64(0x00);
		PushCall(CCONV_FASTCALL, Entrypoint);
	}
	else
	{
		PushInt((INT)BaseAddress);
		PushInt(DLL_PROCESS_ATTACH);
		PushInt(0);
		PushCall(CCONV_STDCALL, Entrypoint);
	}
	
	remote_thread_buffer_t buffer = AssembleRemoteThreadBuffer();

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("\nCallEntryPoint [0x%X]:", Entrypoint);
	#endif 

	return ExecuteRemoteThreadBuffer(buffer);
}

BOOL CRemoteLoader::ProcessImportTable(PVOID BaseAddress, PVOID RemoteAddress)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;

	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, BaseAddress);
		if (ImageImportDescriptor)
		{
			for (; ImageImportDescriptor->Name; ImageImportDescriptor++)
			{
				char* ModuleName = (char*)RvaToPointer(ImageImportDescriptor->Name, BaseAddress);
				if (ModuleName == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessImportTable] Module name for entry NULL");
					#endif
					continue;
				}

				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("[ProcessImportTable] Module Name [%s]", ModuleName);
				#endif

				HMODULE ModuleBase = GetRemoteModuleHandleA(ModuleName);
				if (ModuleBase == NULL)
					ModuleBase = LoadLibraryByPathA(ModuleName); // LoadLibraryByPathA
				if (ModuleBase == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessImportTable] Failed to obtain module handle [%s]", ModuleName);
					#endif
					continue;
				}

				IMAGE_THUNK_DATA *ImageThunkData = NULL;
				IMAGE_THUNK_DATA *ImageFuncData = NULL;

				if (ImageImportDescriptor->OriginalFirstThunk)
				{
					ImageThunkData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->OriginalFirstThunk, BaseAddress);
					ImageFuncData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->FirstThunk, BaseAddress);
				}
				else
				{
					ImageThunkData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->FirstThunk, BaseAddress);
					ImageFuncData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageImportDescriptor->FirstThunk, BaseAddress);
				}


				if (ImageThunkData == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessImportTable] Image Thunk Data is NULL");
					#endif
				}

				if (ImageFuncData == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessImportTable] Image Func Data is NULL");
					#endif
				}

				for (; ImageThunkData->u1.AddressOfData; ImageThunkData++, ImageFuncData++)
				{
					FARPROC FunctionAddress = NULL;

					bool bSnapByOrdinal = false;
					if (m_bIs64bit)
						bSnapByOrdinal = ((ImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0);
					else
						bSnapByOrdinal = ((ImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32) != 0);

					if (bSnapByOrdinal)
					{
						SHORT Ordinal = (SHORT)(ImageThunkData->u1.Ordinal & 0xffff);

						FunctionAddress = (FARPROC)GetRemoteProcAddress(ModuleBase, (const char*)Ordinal); // Utils::GetProcAddress
						
						// Failed to resolve import
						if (FunctionAddress == 0)
						{
							// TODO: Add error code
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessImportTable] Failed to get import [%d] from image [%s]", Ordinal, ModuleName);
							#endif

							return FALSE;
						}

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessImportTable] Processed (%s -> %i) -> (0x%X)", ModuleName, Ordinal, FunctionAddress);
						#endif
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData, BaseAddress);
						char* NameOfImport = (char*)ImageImportByName->Name;

						FunctionAddress = (FARPROC)GetRemoteProcAddress(ModuleBase, NameOfImport); // Utils::GetProcAddress

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessImportTable] Processed (%s -> %s) -> (0x%X)", ModuleName, NameOfImport, FunctionAddress);
						#endif
					}

					ImageFuncData->u1.Function = (size_t)FunctionAddress;
				}
			}
			return TRUE;
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessImportTable] Size of table confirmed but pointer to data invalid!");
			#endif
			return FALSE;
		}
	}
	else
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessImportTable] No Imports");
		#endif
		return TRUE;
	}

	return FALSE;
}

BOOL CRemoteLoader::ProcessDelayedImportTable(PVOID BaseAddress, PVOID RemoteAddress)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;

	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR ImageDelayedImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, BaseAddress);

		if (ImageDelayedImportDescriptor)
		{
			for (; ImageDelayedImportDescriptor->Name; ImageDelayedImportDescriptor++)
			{
				PCHAR ModuleName = (PCHAR)RvaToPointer(ImageDelayedImportDescriptor->Name, BaseAddress);
				if (ModuleName == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessDelayedImportTable] Module name for entry NULL");
					#endif

					continue;
				}

				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("[ProcessDelayedImportTable] Module Name [%s]", ModuleName);
				#endif

				HMODULE ModuleBase = GetRemoteModuleHandleA(ModuleName);
				if (ModuleBase == NULL)
					ModuleBase = LoadLibraryByPathA(ModuleName);  // LoadLibraryByPathA
				if (ModuleBase == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessDelayedImportTable] Failed to obtain module handle for [%s]", ModuleName);
					#endif
					continue;
				}

				IMAGE_THUNK_DATA *ImageThunkData = NULL;
				IMAGE_THUNK_DATA *ImageFuncData = NULL;

				if (ImageDelayedImportDescriptor->OriginalFirstThunk)
				{
					ImageThunkData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->OriginalFirstThunk, BaseAddress);
					ImageFuncData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->FirstThunk, BaseAddress);
				}
				else
				{
					ImageThunkData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->FirstThunk, BaseAddress);
					ImageFuncData = (IMAGE_THUNK_DATA*)RvaToPointer(ImageDelayedImportDescriptor->FirstThunk, BaseAddress);
				}


				if (ImageThunkData == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessDelayedImportTable] Image Thunk Data is NULL");
					#endif
				}

				if (ImageFuncData == NULL)
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessDelayedImportTable] Image Func Data is NULL");
					#endif
				}

				for (; ImageThunkData->u1.AddressOfData; ImageThunkData++, ImageFuncData++)
				{
					FARPROC FunctionAddress = NULL;

					bool bSnapByOrdinal = false;
					if (m_bIs64bit)
						bSnapByOrdinal = ((ImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0);
					else
						bSnapByOrdinal = ((ImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32) != 0);

					if (bSnapByOrdinal)
					{
						WORD Ordinal = (WORD)(ImageThunkData->u1.Ordinal & 0xffff);

						FunctionAddress = (FARPROC)GetRemoteProcAddress(ModuleName, Ordinal); // Utils::GetProcAddress
						// Failed to resolve import
						if (FunctionAddress == 0)
						{
							// TODO: Add error code
							#ifdef DEBUG_MESSAGES_ENABLED
							printf("[ProcessDelayedImportTable] Failed to get import [%d] from image [%s]", Ordinal, ModuleName);
							#endif		
							return FALSE;
						}
						
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessDelayedImportTable] Processed (%s -> %i) -> (0x%X)", ModuleName, Ordinal, FunctionAddress);
						#endif
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData, BaseAddress);

						FunctionAddress = (FARPROC)GetRemoteProcAddress(ModuleName, (PCHAR)ImageImportByName->Name); // Utils::GetProcAddress
						// Failed to resolve import
						if (FunctionAddress == 0)
						{
							// TODO: Add error code
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessDelayedImportTable] Failed to get import [%s] from image [%s]", (PCHAR)ImageImportByName->Name, ModuleName);
							#endif
							return FALSE;
						}

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessDelayedImportTable] Processed (%s -> %s) -> (0x%X)", ModuleName, (PCHAR)ImageImportByName->Name, FunctionAddress);
						#endif
					}

					ImageFuncData->u1.Function = (ULONGLONG)FunctionAddress;
				}
			}

			return TRUE;
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessDelayedImportTable] Size of table confirmed but pointer to data invalid!");
			#endif

			return FALSE;
		}
	}
	else
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessDelayedImportTable] No Delayed Imports");
		#endif

		return TRUE;
	}

	return FALSE;
}

BOOL CRemoteLoader::ProcessRelocation(ULONG ImageBaseDelta, WORD Data, PBYTE RelocationBase)
{
	BOOL bReturn = TRUE;
	switch (IMR_RELTYPE(Data))
	{
	case IMAGE_REL_BASED_HIGH:
	{
		SHORT* Raw = (SHORT*)(RelocationBase + IMR_RELOFFSET(Data));
		SHORT Backup = *Raw;

		*Raw += HIWORD(ImageBaseDelta);

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_HIGH (0x%X) -> (0x%X)", Backup, *Raw);
		#endif

		break;
	}
	case IMAGE_REL_BASED_LOW:
	{
		SHORT* Raw = (SHORT*)(RelocationBase + IMR_RELOFFSET(Data));
		SHORT Backup = *Raw;

		*Raw += LOWORD(ImageBaseDelta);

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_LOW (0x%X) -> (0x%X)", Backup, *Raw);
		#endif

		break;
	}
	case IMAGE_REL_BASED_HIGHLOW:
	{
		size_t* Raw = (size_t*)(RelocationBase + IMR_RELOFFSET(Data));
		size_t Backup = *Raw;

		*Raw += ImageBaseDelta;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_HIGHLOW (0x%X) -> (0x%X)", Backup, *Raw);
		#endif

		break;
	}
	case IMAGE_REL_BASED_DIR64:
	{
		ULONGLONG* Raw = (ULONGLONG*)(RelocationBase + IMR_RELOFFSET(Data));
		ULONGLONG Backup = *Raw;

		*Raw += ImageBaseDelta;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_DIR64 (0x%X) -> (0x%X)", Backup, *Raw);
		#endif

		break;
	}
	case IMAGE_REL_BASED_ABSOLUTE: // No action required
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_ABSOLUTE no need to process");
		#endif
		break;
	}
	case IMAGE_REL_BASED_HIGHADJ: // no action required
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_HIGHADJ no need to process");
		#endif
		break;
	}
	default:
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] UNKNOWN RELOCATION (0x%X)", IMR_RELTYPE(Data));
		#endif

		bReturn = FALSE;

		break;
	}

	} // end of switch

	return bReturn;
}

BOOL CRemoteLoader::ProcessRelocations(PVOID BaseAddress, PVOID RemoteAddress)
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;

	if (ImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocations] Relocations have been stripped from this executable, continuing anyway...");
		#endif
		return TRUE;
	}
	else
	{
		size_t ImageBaseDelta = (size_t)((size_t)RemoteAddress - (size_t)ImageNtHeaders->OptionalHeader.ImageBase);
		if (ImageBaseDelta == 0) // No need to relocate
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessRelocations] No need for relocation");
			#endif
			return TRUE;
		}

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocations] VirtualAddress (0x%X)", ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		#endif

		DWORD RelocationSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocations] Relocation Size [0x%X]", RelocationSize);
		#endif

		if (RelocationSize)
		{
			PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, BaseAddress);
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessRelocations] RelocationDirectory (0x%X)", RelocationDirectory);
			#endif
			
			size_t RelocationEnd = (size_t)RelocationDirectory + RelocationSize;

			RelocData* RelocationStart = reinterpret_cast<RelocData*>(RelocationDirectory);
			if (RelocationStart == nullptr)
			{
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("[ProcessRelocations] Relocations have have not been found in this executable, continuing anyway...");
				#endif
				return TRUE;
			}

			while ((size_t)RelocationStart < RelocationEnd && RelocationStart->SizeOfBlock)
			{
				PBYTE RelocBase = static_cast<PBYTE>(RvaToPointer(RelocationDirectory->VirtualAddress, BaseAddress));
				DWORD NumRelocs = (RelocationStart->SizeOfBlock - 8) >> 1; //sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

				for (DWORD i = 0; i < NumRelocs; ++i)
				{
					WORD fixtype = (RelocationStart->Item[i].Type);              // fixup type
					WORD fixoffset = (RelocationStart->Item[i].Offset) % 4096;   // offset in 4K block

					// no fixup required
					if (fixtype == IMAGE_REL_BASED_ABSOLUTE || fixtype == IMAGE_REL_BASED_HIGHADJ)
						continue;

					// add delta 
					if (fixtype == IMAGE_REL_BASED_HIGHLOW || fixtype == IMAGE_REL_BASED_DIR64)
					{
						size_t* fixRVA = reinterpret_cast<size_t*>((size_t)RelocBase + fixoffset);
						*fixRVA += ImageBaseDelta;
					}
					else
					{
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessRelocation] UNKNOWN RELOCATION (0x%X)", fixtype);
						#endif
						return FALSE;
					}
				}

				RelocationStart = reinterpret_cast<RelocData*>(reinterpret_cast<size_t>(RelocationStart)+RelocationStart->SizeOfBlock);
			}
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessRelocations] Relocations have a size, but the pointer is invalid");
			#endif
			return FALSE;
		}
	}

	return TRUE;
}

ULONG CRemoteLoader::GetSectionProtection(ULONG Characteristics)
{
	ULONG Result = 0;
	if (Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
		Result |= PAGE_NOCACHE;

	if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
	{
		if (Characteristics & IMAGE_SCN_MEM_READ)
		{
			if (Characteristics & IMAGE_SCN_MEM_WRITE)
				Result |= PAGE_EXECUTE_READWRITE;
			else
				Result |= PAGE_EXECUTE_READ;
		}
		else if (Characteristics & IMAGE_SCN_MEM_WRITE)
			Result |= PAGE_EXECUTE_WRITECOPY;
		else
			Result |= PAGE_EXECUTE;
	}
	else if (Characteristics & IMAGE_SCN_MEM_READ)
	{
		if (Characteristics & IMAGE_SCN_MEM_WRITE)
			Result |= PAGE_READWRITE;
		else
			Result |= PAGE_READONLY;
	}
	else if (Characteristics & IMAGE_SCN_MEM_WRITE)
		Result |= PAGE_WRITECOPY;
	else
		Result |= PAGE_NOACCESS;

	return Result;
}

BOOL CRemoteLoader::ProcessSection(BYTE* Name, PVOID BaseAddress, PVOID RemoteAddress, ULONGLONG RawData, ULONGLONG VirtualAddress, ULONGLONG RawSize, ULONGLONG VirtualSize, ULONG ProtectFlag)
{
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[ProcessSection] ProcessSection( %s, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X )", Name, BaseAddress, RemoteAddress, RawData, VirtualAddress, RawSize, VirtualSize, ProtectFlag);
	#endif

	if (WriteProcessMemory(m_hProcess, MakePtr(PVOID, RemoteAddress, VirtualAddress), MakePtr(PVOID, BaseAddress, RawData), RawSize, NULL) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessSection] Failed to write memory for [%s] -> [%s]", Name, LastErrorString());
		#endif
		return FALSE;
	}

	DWORD dwOldProtect = NULL;
	if (VirtualProtectEx(m_hProcess, MakePtr(PVOID, RemoteAddress, VirtualAddress), VirtualSize, ProtectFlag, &dwOldProtect) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessSection] Failed to protect memory for [%s] -> [%s]", Name, LastErrorString());
		#endif
		return FALSE;
	}

	return TRUE;
}

BOOL CRemoteLoader::ProcessSections(PVOID BaseAddress, PVOID RemoteAddress, BOOL MapPEHeader)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;

	// Writing the PE header
	if (MapPEHeader)
	{
		if (WriteProcessMemory(m_hProcess, RemoteAddress, BaseAddress, ImageNtHeaders->OptionalHeader.SizeOfHeaders, NULL) == FALSE)
		{
		#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessSections] Failed to map PE header!");
		}
		else
		{
			DebugShout("[ProcessSections] Mapped PE Header successfully!");
		#endif
		}
	}
	#ifdef DEBUG_MESSAGES_ENABLED
	else
	{
		DebugShout("[ProcessSections] PE Header mapping disabled, skipping.");
	}
	#endif

	// Write individual sections
	PIMAGE_SECTION_HEADER ImageSectionHeader =  (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (DWORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++)
	{	
		if (_stricmp(".reloc", (char*)ImageSectionHeader[i].Name) == 0)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessSections] Skipping \".reloc\" section.");
			#endif
			continue; // NOPE, do not process the .reloc section
		}

		// Skip discardable sections
		if (ImageSectionHeader[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
		{
			ULONG Protection = GetSectionProtection(ImageSectionHeader[i].Characteristics);
			if (ProcessSection(ImageSectionHeader[i].Name, BaseAddress, RemoteAddress, ImageSectionHeader[i].PointerToRawData, ImageSectionHeader[i].VirtualAddress, ImageSectionHeader[i].SizeOfRawData, ImageSectionHeader[i].Misc.VirtualSize, Protection) == FALSE)
			{
			#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("[ProcessSections] Failed [%s]", ImageSectionHeader[i].Name);
			}
			else
			{
				DebugShout("[ProcessSections] Success [%s]", ImageSectionHeader[i].Name);
			#endif
			}
		}
	}

	return TRUE;
}

BOOL CRemoteLoader::ProcessTlsEntries(PVOID BaseAddress, PVOID RemoteAddress)
{
	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;
	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessTlsEntries] No Tls entries to process");
		#endif
		return TRUE; // Success when there is no Tls Entries <--- always hits here
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[ProcessTlsEntries] Tls Data detected!");
	#endif

	PIMAGE_TLS_DIRECTORY TlsDirectory = (PIMAGE_TLS_DIRECTORY)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, BaseAddress);
	if (TlsDirectory == NULL)
		return TRUE; // Success when there is no Tls entries / broken data?

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[ProcessTlsEntries] TlsDirectory (0x%X)", TlsDirectory);
	#endif

	if (TlsDirectory->AddressOfCallBacks == NULL)
		return TRUE; // Success when there is no Tls entries / broken data?

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[ProcessTlsEntries] TlsDirectory->AddressOfCallBacks (0x%X)", TlsDirectory->AddressOfCallBacks);
	#endif

	PIMAGE_TLS_CALLBACK TLSCallbacks[0xFF];
	if (ReadProcessMemory(m_hProcess, (void*)TlsDirectory->AddressOfCallBacks, TLSCallbacks, sizeof(TLSCallbacks), NULL) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessTlsEntries] ReadProcessMemory Failed");
		#endif

		return FALSE;
	}

	BOOL SuccessValue = TRUE;
	for (int i = 0; TLSCallbacks[i]; i++)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessTlsEntries] TLSCallbacks[%i] = 0x%X (0x%X)", i, TLSCallbacks[i], RemoteAddress);
		#endif

		// As a consequence of the relocation stuff mentioned above, pCallbacks[i] is already fixed
		if (CallEntryPoint(RemoteAddress, (FARPROC)TLSCallbacks[i]) == false)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessTlsEntries] Failed to execute Tls Entry [%i]", i);
		}
		else
		{
			DebugShout("[ProcessTlsEntries] Called Tls Callback (0x%X)", TLSCallbacks[i]);
			#endif
		}
	}

	return SuccessValue;
}

///////////////////////
// Private functions //
///////////////////////
ModuleFile CRemoteLoader::InitModuleFile(LPCCH FileName)
{
	ModuleFile r;

	r.Buffer = 0;
	r.Size = 0;

	HANDLE hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[InitModuleFile] CreateFile Failed");
		#endif
		return r;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[InitModuleFile] File opened");
	#endif

	if (GetFileAttributesA(FileName) & FILE_ATTRIBUTE_COMPRESSED)
	{
		r.Size = GetCompressedFileSizeA(FileName, NULL);
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[InitModuleFile] File is compressed!");
		#endif
	}
	else
	{
		r.Size = GetFileSize(hFile, NULL);
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[InitModuleFile] Size [0x%X]", r.Size);
	#endif

	if (r.Size == 0)
	{
		CloseHandle(hFile);
		return r;
	}

	unsigned char* AllocatedFile = (unsigned char*)VirtualAlloc(NULL, r.Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (AllocatedFile == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[InitModuleFile] Failed to allocate buffer!");
		#endif

		r.Size = 0;
		CloseHandle(hFile);
		return r;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[InitModuleFile] Buffer allocated!");
	#endif

	DWORD NumberOfBytesRead = 0;
	if (ReadFile(hFile, AllocatedFile, r.Size, &NumberOfBytesRead, FALSE) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[InitModuleFile] Read file failed");
		#endif

		r.Buffer = 0;
		r.Size = 0;
	}
	else
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[InitModuleFile] Read file complete [0x%X]", NumberOfBytesRead);
		#endif

		r.Buffer = AllocatedFile;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[InitModuleFile] Buffer [0x%X]", r.Buffer);
	#endif
	
	CloseHandle(hFile);

	return r;
}

BOOL CRemoteLoader::FreeModuleFile(ModuleFile Handle)
{
	if (Handle.Buffer)
	{
		VirtualFree(Handle.Buffer, Handle.Size, MEM_RELEASE);
		Handle.Buffer = 0;
	}

	Handle.Size = 0;

	return (Handle.Buffer == 0 && Handle.Size == 0);
}

TCHAR* CRemoteLoader::LastErrorString()
{
	TCHAR* returnBuffer = 0;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&returnBuffer, 0, NULL);
	return returnBuffer;
}

int CRemoteLoader::GetProcessPlatform()
{
	if (m_hProcess == (HANDLE)((LONG_PTR)-1))
	{
		#if defined(_M_IX86)
		return 1; // ProcessPlatformX86;
		#elif defined(_M_X64)
		return 2; // ProcessPlatformX64
		#endif
	}
	switch (Utils::GetProcessorArchitecture())
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		return 1; // ProcessPlatformX86;
	case PROCESSOR_ARCHITECTURE_AMD64:
		//check on 64-bit platforms
		ULONG_PTR nWow64;
		NTSTATUS nNtStatus;

		nNtStatus = fnNTQIP(m_hProcess, ProcessWow64Information, &nWow64, sizeof(nWow64), NULL);
		if (NT_SUCCESS(nNtStatus))
		{
			#if defined(_M_IX86)
			return (nWow64 == 0) ? 2 : 1;
			#elif defined(_M_X64)
			return (nWow64 != 0) ? 1 : 2;
			#endif
		}
		#if defined(_M_IX86)
		return 1;
		#elif defined(_M_X64)
		return 2;
		#endif
		break;
		//case PROCESSOR_ARCHITECTURE_IA64:
		//case PROCESSOR_ARCHITECTURE_ALPHA64:
	}
	return STATUS_NOT_SUPPORTED;
}