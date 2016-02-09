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
	m_hProcess = hProcess;
	
	HMODULE hNtDll = (HMODULE)Utils::getLocalModuleHandle("ntdll.dll");
	fnNTQIP = (tNTQIP)Utils::getProcAddress(hNtDll, "NtQueryInformationProcess");
	fnNTQSI = (tNTQSI)Utils::getProcAddress(hNtDll, "NtQuerySystemInformation");

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
	
	typedef HMODULE(__stdcall *tLoadLibraryW)(LPCWSTR lpLibFileName);

	//tLoadLibraryW RemoteLoadLibraryW = (tLoadLibraryW)Utils::getProcAddress(Utils::getLocalModuleHandle("kernel32.dll"), "LoadLibraryW");
	//if (RemoteLoadLibraryW == NULL)
	//{
	//	#ifdef DEBUG_MESSAGES_ENABLED
	//	DebugShout("[LoadLibraryByPathW] LoadLibraryW Resolve Failure");
	//	#endif
	//	return NULL;
	//}

	HMODULE RemoteModuleHandle = LoadLibraryW(Path);
	if (RemoteModuleHandle == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] LoadLibraryW Resolve Failure");
		#endif
		return NULL;
	}

	//FARPROC RemoteLoadLibraryW = GetRemoteProcAddress("kernel32.dll", "LoadLibraryW");
	//if (RemoteLoadLibraryW == NULL)
	//{
	//	#ifdef DEBUG_MESSAGES_ENABLED
	//	DebugShout("[LoadLibraryByPathW] LoadLibraryW Resolve Failure");
	//	#endif
	//	return NULL;
	//
	//	//RemoteLoadLibraryW = (FARPROC)Utils::getProcAddress(Utils::getLocalModuleHandle("kernel32.dll"), "LoadLibraryW");
	//	//if (RemoteLoadLibraryW == NULL)
	//	//{
	//	//	#ifdef DEBUG_MESSAGES_ENABLED
	//	//	DebugShout("[LoadLibraryByPathW] LoadLibraryW Resolve Failure");
	//	//	#endif
	//	//	return NULL;
	//	//}
	//}
	//
	//void* ReturnPointerValue = RemoteAllocateMemory(sizeof(void*));
	//
	//PushUNICODEString(Path);
	//PushCall(CCONV_STDCALL, RemoteLoadLibraryW);
	//
	//if (m_bIs64bit)
	//{
	//	//mov ptr, rax
	//	AddByteToBuffer(0x48);
	//	AddByteToBuffer(0xA3);
	//	AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);
	//
	//	//xor rax, rax
	//	AddByteToBuffer(0x48);
	//	AddByteToBuffer(0x33);
	//	AddByteToBuffer(0xC0);
	//
	//	// retn 8 in 64bit
	//	AddByteToBuffer(0xC2);
	//	AddByteToBuffer(0x08);
	//	AddByteToBuffer(0x00);
	//}
	//else
	//{
	//	//mov ptr, eax
	//	AddByteToBuffer(0xA3);
	//	AddLongToBuffer((unsigned long)ReturnPointerValue);
	//
	//	//xor eax, eax
	//	AddByteToBuffer(0x33);
	//	AddByteToBuffer(0xC0);
	//
	//	//retn 4
	//	AddByteToBuffer(0xC2);
	//	AddByteToBuffer(0x04);
	//	AddByteToBuffer(0x00);
	//}
	//
	//#ifdef DEBUG_MESSAGES_ENABLED
	//DebugShout("[LoadLibraryByPathW] LoadLibraryW = 0x%X", RemoteLoadLibraryW);
	//#endif
	//
	//if (ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true) == false)
	//{
	//	#ifdef DEBUG_MESSAGES_ENABLED
	//	DebugShout("[LoadLibraryByPathW] ExecuteRemoteThreadBuffer failed");
	//	#endif
	//
	//	RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
	//
	//	return NULL;
	//}
	//
	//#ifdef DEBUG_MESSAGES_ENABLED
	//DebugShout("[LoadModuleByNameW] ExecuteRemoteThreadBuffer succeeded");
	//#endif
	//
	//DWORD_PTR RemoteModuleHandle = 0;
	//if (ReadProcessMemory(GetProcess(), ReturnPointerValue, &RemoteModuleHandle, sizeof(void*), NULL) == TRUE)
	//{
	//	RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
	//}
	//else
	//{
	//	RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
	//	if (RemoteModuleHandle == 0)
	//		RemoteModuleHandle = (DWORD_PTR)GetRemoteModuleHandleW(Path);
	//}

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
							sprintf_s(dbgOut, "Could not read list entry from LDR list. Error = %X", GetLastError());
							MessageBox(0, dbgOut, "Injectora DBG", MB_ICONERROR);
							#endif

							if (pbi)
								HeapFree(hHeap, 0, pbi);
							return NULL;
						}

						pLdrCurrentNode = lstEntry.InLoadOrderLinks.Flink;

						//wchar_t wcsFullDllName[MAX_PATH] = { 0 };
						//char strFullDllName[MAX_PATH] = { 0 };
						//if (lstEntry.FullDllName.Length > 0)
						//{
						//	dwBytesRead = 0;
						//	if (ReadProcessMemory(m_hProcess, (void*)lstEntry.FullDllName.Buffer, &wcsFullDllName, lstEntry.FullDllName.Length, &dwBytesRead))
						//	{
						//		size_t bytesCopied = 0;
						//		wcstombs_s(&bytesCopied, strFullDllName, wcsFullDllName, MAX_PATH);
						//		#ifdef _DEBUG
						//		printf("Full Dll Name: %s\n", strFullDllName);
						//		#endif
						//	}
						//}

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

FARPROC CRemoteLoader::GetRemoteProcAddress(LPCCH Module, LPCCH Function)
{
	HMODULE hKernel32 = LoadLibrary("Kernel32.dll");
	if (hKernel32 == NULL)
		return NULL;

	DWORD GetProcAddressOffset = (DWORD)((DWORD_PTR)GetProcAddress - (DWORD_PTR)hKernel32);

	HMODULE hRemoteKernel32 = GetRemoteModuleHandleA("Kernel32.dll");
	if (hRemoteKernel32 == NULL)
		return NULL;

	HMODULE hRemoteModule = GetRemoteModuleHandleA(Module);
	if (hRemoteModule == NULL)
		return NULL;

	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(void*));

	if (m_bIs64bit)
		PushInt64((__int64)hRemoteModule);
	else
		PushInt((__int32)hRemoteModule);

	PushANSIString(Function);
	if (m_bIs64bit)
	{
		PushCall(CCONV_FASTCALL, (FARPROC)((DWORD_PTR)hRemoteKernel32 + (DWORD_PTR)GetProcAddressOffset));

		//mov ptr, rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);

		//xor rax, rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);

		// retn 8 in 64bit
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x08);
		AddByteToBuffer(0x00);
	}
	else
	{	
		PushCall(CCONV_STDCALL, (FARPROC)((DWORD_PTR)hRemoteKernel32 + (DWORD_PTR)GetProcAddressOffset));

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

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("\n\nGetRemoteProcAddress [%s][%s]:", Module, Function);
	#endif

	if (ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true) == false)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
		return NULL;
	}

	DWORD_PTR ProcAddressRemote = 0;
	if (ReadProcessMemory(m_hProcess, ReturnPointerValue, &ProcAddressRemote, sizeof(void*), NULL) == TRUE)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
		
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("GetRemoteProcAddress [%s][%s] -> (0x%X)", Module, Function, (void*)ProcAddressRemote);
		#endif

		return (FARPROC)ProcAddressRemote;
	}

	RemoteFreeMemory(ReturnPointerValue, sizeof(void*));

	return NULL;
}

FARPROC CRemoteLoader::GetRemoteProcAddress(LPCCH Module, SHORT Function)
{
	HMODULE hKernel32 = LoadLibraryA("Kernel32.dll");
	if (hKernel32 == NULL) 
		return NULL;

	DWORD GetProcAddressOffset = (DWORD)((DWORD_PTR)GetProcAddress - (DWORD_PTR)hKernel32);

	HMODULE hRemoteKernel32 = GetRemoteModuleHandleA("Kernel32.dll");
	if (hRemoteKernel32 == NULL) 
		return NULL;

	HMODULE hRemoteModule = GetRemoteModuleHandleA(Module);
	if (hRemoteModule == NULL)
		return NULL;

	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(void*));
	if (m_bIs64bit)
	{
		PushInt64((__int64)hRemoteModule); // HACKHACK: Why is this an int? Should be VOID* ??
		PushInt64((__int64)Function);
	}
	else
	{
		PushInt((INT)hRemoteModule); // HACKHACK: Why is this an int? Should be VOID* ??
		PushInt((INT)Function);
	}

	PushCall(CCONV_STDCALL, (FARPROC)((DWORD_PTR)hRemoteKernel32 + (DWORD_PTR)GetProcAddressOffset));

	if (m_bIs64bit)
	{
		//mov ptr, rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((DWORD64)ReturnPointerValue);

		//xor rax, rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);

		// retn 8 in 64bit
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x08);
		AddByteToBuffer(0x00);
	}
	else
	{
		//mov ptr, eax
		AddByteToBuffer(0xA3);
		AddLongToBuffer((DWORD)ReturnPointerValue);

		//xor eax, eax
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);

		//retn 4
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x04);
		AddByteToBuffer(0x00);
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("\n\nGetRemoteProcAddress [%s][0x%X]:", Module, (DWORD)Function);
	#endif

	if (ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true) == false)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));
		return NULL;
	}

	DWORD ProcAddressRemote = 0;
	if (ReadProcessMemory(GetProcess(), ReturnPointerValue, &ProcAddressRemote, sizeof(void*), NULL) == TRUE)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("GetRemoteProcAddress [%s][0x%X] -> (0x%X)", Module, (void*)Function, (void*)ProcAddressRemote);
		#endif

		return (FARPROC)ProcAddressRemote;
	}

	RemoteFreeMemory(ReturnPointerValue, sizeof(void*));

	return NULL;
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

ExportData CRemoteLoader::GetExport(void* BaseAddress, const char* name_ord, const char* baseModule /*= ""*/)
{
	ExportData data;
	// Invalid module
	if (BaseAddress == 0)
		return data;

	IMAGE_DOS_HEADER hdrDos = { 0 };
	unsigned char hdrNt32[sizeof(IMAGE_NT_HEADERS64)] = { 0 };
	PIMAGE_NT_HEADERS32 phdrNt32 = (PIMAGE_NT_HEADERS32)(hdrNt32);
	PIMAGE_NT_HEADERS64 phdrNt64 = (PIMAGE_NT_HEADERS64)(hdrNt32);
	DWORD expSize = 0;
	size_t expBase = 0;
	SIZE_T dwDummyBytes = 0;

	ReadProcessMemory(m_hProcess, (void*)BaseAddress, &hdrDos, sizeof(hdrDos), &dwDummyBytes);
	if (hdrDos.e_magic != IMAGE_DOS_SIGNATURE)
		return data; // wtf??

	ReadProcessMemory(m_hProcess, (void*)((DWORD_PTR)BaseAddress + hdrDos.e_lfanew), &hdrNt32, sizeof(IMAGE_NT_HEADERS64), &dwDummyBytes);
	if (phdrNt32->Signature != IMAGE_NT_SIGNATURE)
		return data;

	if (phdrNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		expBase = phdrNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	else
		expBase = phdrNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	// Exports are present
	if (expBase)
	{
		if (phdrNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) 
			expSize = phdrNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size; // 32 bit
		else
			expSize = phdrNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size; // 64 bit

		IMAGE_EXPORT_DIRECTORY* pExpData = (IMAGE_EXPORT_DIRECTORY*)malloc(expSize);

		ReadProcessMemory(m_hProcess, (void*)((DWORD_PTR)BaseAddress + expBase), pExpData, expSize, &dwDummyBytes);

		WORD* pAddressOfOrds   = (WORD*)(pExpData->AddressOfNameOrdinals + (size_t)pExpData - expBase);
		DWORD* pAddressOfNames = (DWORD*)(pExpData->AddressOfNames + (size_t)pExpData - expBase);
		DWORD* pAddressOfFuncs = (DWORD*)(pExpData->AddressOfFunctions + (size_t)pExpData - expBase);

		for (DWORD i = 0; i < pExpData->NumberOfFunctions; ++i)
		{
			WORD OrdIndex = 0xFFFF;
			char *pName = nullptr;

			// Find by index
			if ((size_t)name_ord <= 0xFFFF)
			{
				OrdIndex = (WORD)i;
			}
			// Find by name
			else if ((size_t)name_ord > 0xFFFF && i < pExpData->NumberOfNames)
			{
				pName = (char*)(pAddressOfNames[i] + (DWORD_PTR)pExpData - expBase);
				OrdIndex = (WORD)pAddressOfOrds[i];
			}
			else
				return data;

			if (((size_t)name_ord <= 0xFFFF && (size_t)(name_ord) == (size_t)(OrdIndex + pExpData->Base)) || ((size_t)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
			{
				data.procAddress = pAddressOfFuncs[OrdIndex] + (DWORD_PTR)BaseAddress;
				
				// Check forwarded export
				if (data.procAddress >= (DWORD_PTR)BaseAddress + expBase && data.procAddress <= (DWORD_PTR)BaseAddress + expBase + expSize)
				{
					char forwardStr[255] = { 0 };
					SIZE_T dummyBytes;

					ReadProcessMemory(m_hProcess, (void*)data.procAddress, forwardStr, sizeof(forwardStr), &dummyBytes);

					std::string chainExp(forwardStr);

					std::string strDll = chainExp.substr(0, chainExp.find(".")) + ".dll";
					std::string strName = chainExp.substr(chainExp.find(".") + 1, strName.npos);

					// Fill export data info
					data.isForwarded = true;
					data.forwardModule = strDll.c_str();
					data.forwardByOrd = (strName.find("#") == 0);

					if (data.forwardByOrd)
						data.forwardOrdinal = static_cast<WORD>(atoi(strName.c_str() + 1));
					else
						data.forwardName = strName.c_str();

					//int mt = (phdrNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ? 0 : 1;
					HMODULE hChainModule = GetRemoteModuleHandleA(strDll.c_str());
					if (hChainModule == nullptr)
						return data;

					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[GetExport] %s[%i] >> Forwarded -> %s -> %s -> ( 0x%X )", pName, OrdIndex, data.forwardModule, data.forwardName, data.procAddress);
					#endif

					// Import by ordinal
					if (data.forwardByOrd)
						return GetExport(hChainModule, (const char*)data.forwardOrdinal, strDll.c_str());
					else // Import by name
						return GetExport(hChainModule, strName.c_str(), strDll.c_str());
				}
				else
				{
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[GetExport] %s[%i] -> (0x%X)", pName, OrdIndex, data.procAddress);
					#endif
				}

				break;
			}
		}
	}

	return data;

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
					ModuleBase = LoadLibraryByPathA(ModuleName);
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

						ExportData expData = GetExport(ModuleBase, (const char*)Ordinal);

						// Still forwarded, load missing modules
						while (expData.procAddress && expData.isForwarded)
						{
							std::string dllpath = expData.forwardModule;

							// Ensure module is loaded
							HMODULE hFwdMod = GetRemoteModuleHandleA((PCHAR)dllpath.c_str());
							if (hFwdMod == NULL)
							{
								hFwdMod = LoadLibraryByPathA((PCHAR)dllpath.c_str());
							}

							if (!hFwdMod)
							{
								// TODO: Add error code
								#ifdef DEBUG_MESSAGES_ENABLED
								printf("[ProcessDelayedImportTable] Failed to load forwarded dependency [%s]", ModuleName);
								#endif

								return FALSE;
							}

							if (expData.forwardByOrd)
								expData = GetExport(hFwdMod, (const char*)expData.forwardOrdinal, dllpath.c_str());
							else
								expData = GetExport(hFwdMod, expData.forwardName, dllpath.c_str());
						}

						// Failed to resolve import
						if (expData.procAddress == 0)
						{
							// TODO: Add error code
							#ifdef DEBUG_MESSAGES_ENABLED
							printf("[ProcessDelayedImportTable] Failed to get import [%d] from image [%s]", Ordinal, ModuleName);
							#endif
							
							return FALSE;
						}

						FunctionAddress = (FARPROC)expData.procAddress;//(FARPROC)GetRemoteProcAddress(ModuleName, Ordinal);
						
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessDelayedImportTable] Processed (%s -> %i) -> (0x%X)", ModuleName, Ordinal, FunctionAddress);
						#endif

						if (m_hProcess == INVALID_HANDLE_VALUE)
						{
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessDelayedImportTable] Normal Value (0x%X)", GetProcAddress(GetModuleHandleA(ModuleName), (LPCSTR)Ordinal));
							#endif
						}
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData, BaseAddress);

						ExportData expData = GetExport(ModuleBase, (const char*)ImageImportByName->Name);

						// Still forwarded, load missing modules
						while (expData.procAddress && expData.isForwarded)
						{
							std::string dllpath = expData.forwardModule;

							// Ensure module is loaded
							HMODULE hFwdMod = GetRemoteModuleHandleA((PCHAR)dllpath.c_str());
							if (hFwdMod == NULL)
							{
								hFwdMod = LoadLibraryByPathA((PCHAR)dllpath.c_str());
							}

							if (!hFwdMod)
							{
								// TODO: Add error code
								#ifdef DEBUG_MESSAGES_ENABLED
								DebugShout("[ProcessDelayedImportTable] Failed to load forwarded dependency [%s]", ModuleName);
								#endif
								
								return FALSE;
							}

							if (expData.forwardByOrd)
								expData = GetExport(hFwdMod, (const char*)expData.forwardOrdinal, dllpath.c_str());
							else
								expData = GetExport(hFwdMod, expData.forwardName, dllpath.c_str());
						}

						// Failed to resolve import
						if (expData.procAddress == 0)
						{
							// TODO: Add error code
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessDelayedImportTable] Failed to get import [%s] from image [%s]", (PCHAR)ImageImportByName->Name, ModuleName);
							#endif

							return FALSE;
						}

						FunctionAddress = (FARPROC)expData.procAddress;

						//FunctionAddress = (FARPROC)GetRemoteProcAddress(ModuleName, (PCHAR)ImageImportByName->Name);

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessDelayedImportTable] Processed (%s -> %s) -> (0x%X)", ModuleName, (PCHAR)ImageImportByName->Name, FunctionAddress);
						#endif

						if (this->GetProcess() == INVALID_HANDLE_VALUE)
						{
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessDelayedImportTable] Normal Value (0x%X)", GetProcAddress(GetModuleHandleA(ModuleName), (PCHAR)ImageImportByName->Name));
							#endif
						}
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
					ModuleBase = LoadLibraryA(ModuleName); // LoadLibraryByPathA
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

						ExportData expData = GetExport(ModuleBase, (const char*)Ordinal);

						// Still forwarded, load missing modules
						while (expData.procAddress && expData.isForwarded)
						{
							const char* dllpath = expData.forwardModule;

							// Ensure module is loaded
							HMODULE hFwdMod = GetRemoteModuleHandleA(dllpath);
							if (hFwdMod == NULL)
								hFwdMod = LoadLibraryA((PCHAR)dllpath); // LoadLibraryByPathA

							if (!hFwdMod)
							{
								// TODO: Add error code
								#ifdef DEBUG_MESSAGES_ENABLED
								DebugShout("[ProcessImportTable] Failed to load forwarded dependency [%s]", ModuleName);
								#endif

								return FALSE;
							}

							if (expData.forwardByOrd)
								expData = GetExport(hFwdMod, (const char*)expData.forwardOrdinal, dllpath);
							else
								expData = GetExport(hFwdMod, expData.forwardName, dllpath);
						}

						// Failed to resolve import
						if (expData.procAddress == 0)
						{
							// TODO: Add error code
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessImportTable] Failed to get import [%d] from image [%s]", Ordinal, ModuleName);
							#endif

							return FALSE;
						}

						FunctionAddress = (FARPROC)expData.procAddress;
						//FunctionAddress = (FARPROC)GetRemoteProcAddress(ModuleName, Ordinal);
						
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessImportTable] Processed (%s -> %i) -> (0x%X)", ModuleName, Ordinal, FunctionAddress);
						#endif

						if (this->GetProcess() == INVALID_HANDLE_VALUE)
						{
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessImportTable] Normal Value (0x%X)", GetProcAddress(GetModuleHandleA(ModuleName), (LPCSTR)Ordinal));
							#endif
						}
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData, BaseAddress);
						char* NameOfImport = (char*)ImageImportByName->Name;

						//ExportData expData = GetExport(ModuleBase, (const char*)ImageImportByName->Name);
						//// Still forwarded, load missing modules
						//while (expData.procAddress && expData.isForwarded)
						//{
						//	std::string dllpath = expData.forwardModule;
						//
						//	// Ensure module is loaded
						//	HMODULE hFwdMod = GetRemoteModuleHandleA((PCHAR)dllpath.c_str());
						//	if (hFwdMod == NULL)
						//		hFwdMod = LoadLibraryA((PCHAR)dllpath.c_str()); // LoadLibraryByPathA
						//	if (hFwdMod == NULL)
						//	{
						//		// TODO: Add error code
						//		#ifdef DEBUG_MESSAGES_ENABLED
						//		DebugShout("[ProcessImportTable] Failed to load forwarded dependency [%s]", ModuleName);
						//		#endif
						//		return FALSE;
						//	}
						//
						//	if (expData.forwardByOrd)
						//		expData = GetExport(hFwdMod, (const char*)expData.forwardOrdinal, dllpath.c_str());
						//	else
						//		expData = GetExport(hFwdMod, expData.forwardName, dllpath.c_str());
						//}
						//
						//// Failed to resolve import
						//if (expData.procAddress == 0)
						//{
						//	// TODO: Add error code
						//	#ifdef DEBUG_MESSAGES_ENABLED
						//	DebugShout("[ProcessImportTable] Failed to get import [%s] from image [%s]", (PCHAR)ImageImportByName->Name, ModuleName);			
						//	#endif
						//
						//	return FALSE;
						//}

						//FunctionAddress = (FARPROC)expData.procAddress;			
						FunctionAddress = (FARPROC)Utils::getProcAddress(ModuleBase, NameOfImport);

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessImportTable] Processed (%s -> %s) -> (0x%X)", ModuleName, NameOfImport, FunctionAddress);
						#endif

						if (m_hProcess == INVALID_HANDLE_VALUE)
						{
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessImportTable] Normal Value (0x%X)", GetProcAddress(GetModuleHandleA(ModuleName), NameOfImport));
							#endif
						}
					}

					ImageFuncData->u1.Function = (ULONGLONG)FunctionAddress;
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
			DebugShout("[ProcessRelocations] No need for relocation");
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

	//DWORD dwOldProtect = NULL;
	//if (VirtualProtectEx(m_hProcess, MakePtr(PVOID, RemoteAddress, VirtualAddress), VirtualSize, ProtectFlag, &dwOldProtect) == FALSE)
	//{
	//	#ifdef DEBUG_MESSAGES_ENABLED
	//	DebugShout("[ProcessSection] Failed to protect memory for [%s] -> [%s]", Name, LastErrorString());
	//	#endif
	//	return FALSE;
	//}

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

LONG CRemoteLoader::GetProcessorArchitecture()
{
	static LONG volatile nProcessorArchitecture = -1;
	if (nProcessorArchitecture == -1)
	{
		SYSTEM_PROCESSOR_INFORMATION sProcInfo;
		NTSTATUS nNtStatus;

		tRtlGetNativeSystemInformation fnRtlGetNativeSystemInformation = (tRtlGetNativeSystemInformation)Utils::getProcAddress((HMODULE)Utils::getLocalModuleHandle("ntdll.dll"), "RtlGetNativeSystemInformation");

		nNtStatus = fnRtlGetNativeSystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo, sizeof(sProcInfo), NULL);
		if (nNtStatus == STATUS_NOT_IMPLEMENTED)
		{
			nNtStatus = fnNTQSI((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo, sizeof(sProcInfo), NULL);
		}
		if (NT_SUCCESS(nNtStatus))
			_InterlockedExchange(&nProcessorArchitecture, (LONG)(sProcInfo.ProcessorArchitecture));
	}
	return nProcessorArchitecture;
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
	switch (GetProcessorArchitecture())
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