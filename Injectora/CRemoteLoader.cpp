#include "CRemoteLoader.h"

#include <Tlhelp32.h>
#include <DbgHelp.h>

#pragma comment (lib, "DbgHelp.lib")

#ifdef UNICODE
#undef UNICODE
#endif

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define MakeDelta(cast, x, y) (cast) ( (DWORD_PTR)(x) - (DWORD_PTR)(y))

// ######################
// ## Public functions ##
// ######################

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
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] LoadLibraryW Resolve Failure");
		#endif

		return NULL;
	}

	#ifdef _WIN64
	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(DWORD64));
	#else
	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(DWORD));
	#endif

	PushUNICODEString(Path);

	PushCall(CCONV_STDCALL, RemoteLoadLibraryW);

	//mov ptr, eax
	AddByteToBuffer(0xA3);
	#ifdef _WIN64
	AddLong64ToBuffer((DWORD64)ReturnPointerValue);
	#else
	AddLongToBuffer((DWORD)ReturnPointerValue);
	#endif

	//xor eax, eax
	AddByteToBuffer(0x33);
	AddByteToBuffer(0xC0);

	//retn 4
	AddByteToBuffer(0xC2);
	AddByteToBuffer(0x04);
	AddByteToBuffer(0x00);

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryByPathW] LoadLibraryW = 0x%X", RemoteLoadLibraryW);
	#endif

	if (ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true) == false)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] ExecuteRemoteThreadBuffer failed");
		#endif

		RemoteFreeMemory(ReturnPointerValue, sizeof(DWORD));

		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleByNameW] ExecuteRemoteThreadBuffer succeeded");
	#endif

	DWORD RemoteModuleHandle = 0;

	if (ReadProcessMemory(GetProcess(), ReturnPointerValue, &RemoteModuleHandle, sizeof(DWORD), NULL) == TRUE)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(DWORD));
	}
	else
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(DWORD));

		if (RemoteModuleHandle == 0)
		{
			RemoteModuleHandle = (DWORD)GetRemoteModuleHandleW(Path);
		}
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

	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size)
	{
		if (ImageDirectoryEntryToData(BaseAddress, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR))
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadLibraryFromMemory] This method is not supported for Managed executables!");
			#endif

			return NULL;
		}
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] No COM/CLR data found!");
	#endif

	// SizeOfImage NOT the same as module size MOTHERFUCKER
	// http://www.youtube.com/watch?v=pele5vptVgc

	PVOID AllocatedRemoteMemory = RemoteAllocateMemory(ImageNtHeaders->OptionalHeader.SizeOfImage);
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

	printf("Processed Import Tables Successfully!!\n");

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
HMODULE CRemoteLoader::GetRemoteModuleHandleA(LPCCH Module)
{
	HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(GetProcess()));

	MODULEENTRY32 modEntry;

	modEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(tlh, &modEntry);
	do
	{
		if (_stricmp(Module, modEntry.szModule) == 0)
		{
			CloseHandle(tlh);
			return modEntry.hModule;
		}
	} while (Module32Next(tlh, &modEntry));

	CloseHandle(tlh);

	return NULL;
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

#ifdef _WIN64
	PushInt64((__int64)hRemoteModule);
#else
	PushInt((__int32)hRemoteModule);
#endif
	PushANSIString(Function);
	PushCall(CCONV_STDCALL, (FARPROC)((DWORD_PTR)hRemoteKernel32 + (DWORD_PTR)GetProcAddressOffset));

	
#ifdef _WIN64
	//mov ptr, rax
	AddByteToBuffer(0x48);
	AddByteToBuffer(0xA3);
	AddLong64ToBuffer((DWORD64)ReturnPointerValue);
#else
	//mov ptr, eax
	AddByteToBuffer(0xA3);
	AddLongToBuffer((DWORD)ReturnPointerValue);
#endif
	
#ifdef _WIN64
	//xor rax, rax
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x33);
	AddByteToBuffer(0xC0);
#else
	//xor eax, eax
	AddByteToBuffer(0x33);
	AddByteToBuffer(0xC0);
#endif

#ifdef _WIN64
	// retn 8 in 64bit
	AddByteToBuffer(0xC2);
	AddByteToBuffer(0x08);
	AddByteToBuffer(0x00);
#else
	//retn 4
	AddByteToBuffer(0xC2);
	AddByteToBuffer(0x04);
	AddByteToBuffer(0x00);
#endif

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("\n\nGetRemoteProcAddress [%s][%s]:", Module, Function);
	#endif

	if (ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true) == false)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(void*));

		return NULL;
	}

#ifdef _WIN64
	unsigned __int64 ProcAddressRemote = 0;
#else
	DWORD ProcAddressRemote = 0;
#endif

	if (ReadProcessMemory(GetProcess(), ReturnPointerValue, &ProcAddressRemote, sizeof(void*), NULL) == TRUE)
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
	return ImageRvaToVa(ImageNtHeaders, BaseAddress, RVA, 0);
}

PVOID CRemoteLoader::ImageDirectoryEntryToData(PVOID BaseAddress, USHORT DataDirectory)
{
	ULONG dummySize = 0;
	return ::ImageDirectoryEntryToData(BaseAddress, TRUE, DataDirectory, &dummySize);
}

BOOL CRemoteLoader::CallEntryPoint(void* BaseAddress, FARPROC Entrypoint)
{
	if (m_bIs64bit)
		PushInt64((__int64)BaseAddress);
	else
		PushInt((INT)BaseAddress);

	PushInt(DLL_PROCESS_ATTACH);
	PushInt(0);
	PushCall(CCONV_STDCALL, Entrypoint);
	
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
		return data;

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

		WORD* pAddressOfOrds = (WORD*)(pExpData->AddressOfNameOrdinals + (size_t)pExpData - expBase);
		DWORD_PTR* pAddressOfNames = (DWORD_PTR*)(pExpData->AddressOfNames + (size_t)pExpData - expBase);
		DWORD_PTR* pAddressOfFuncs = (DWORD_PTR*)(pExpData->AddressOfFunctions + (size_t)pExpData - expBase);

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
				pName = (char*)(pAddressOfNames[i] + (size_t)pExpData - expBase);
				OrdIndex = (WORD)pAddressOfOrds[i];
			}
			else
				return data;

			if (((size_t)name_ord <= 0xFFFF && (WORD)((unsigned int)name_ord) == (OrdIndex + pExpData->Base)) || ((size_t)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
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

						if (this->GetProcess() == INVALID_HANDLE_VALUE)
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

					ImageFuncData->u1.Function = (DWORD)FunctionAddress;
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
				PCHAR ModuleName = (PCHAR)RvaToPointer(ImageImportDescriptor->Name, BaseAddress);
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
					ModuleBase = LoadLibraryByPathA(ModuleName);
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
								hFwdMod = LoadLibraryByPathA((PCHAR)dllpath);

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
						PCHAR NameOfImport = (PCHAR)ImageImportByName->Name;
						ExportData expData = GetExport(ModuleBase, (const char*)ImageImportByName->Name);

						// Still forwarded, load missing modules
						while (expData.procAddress && expData.isForwarded)
						{
							std::string dllpath = expData.forwardModule;

							// Ensure module is loaded
							HMODULE hFwdMod = GetRemoteModuleHandleA((PCHAR)dllpath.c_str());
							if (hFwdMod == NULL)
								hFwdMod = LoadLibraryByPathA((PCHAR)dllpath.c_str());
							if (hFwdMod == NULL)
							{
								// TODO: Add error code
								#ifdef DEBUG_MESSAGES_ENABLED
								DebugShout("[ProcessImportTable] Failed to load forwarded dependency [%s]", ModuleName);
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
							DebugShout("[ProcessImportTable] Failed to get import [%s] from image [%s]", (PCHAR)ImageImportByName->Name, ModuleName);			
							#endif

							return FALSE;
						}

						FunctionAddress = (FARPROC)expData.procAddress;

						//FunctionAddress = (FARPROC)GetRemoteProcAddress(ModuleName, NameOfImport);

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessImportTable] Processed (%s -> %s) -> (0x%X)", ModuleName, NameOfImport, FunctionAddress);
						#endif

						if (this->GetProcess() == INVALID_HANDLE_VALUE)
						{
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessImportTable] Normal Value (0x%X)", GetProcAddress(GetModuleHandleA(ModuleName), NameOfImport));
							#endif
						}
					}

					ImageFuncData->u1.Function = (DWORD)FunctionAddress;
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

BOOL CRemoteLoader::ProcessRelocation(INT ImageBaseDelta, WORD Data, PBYTE RelocationBase)
{
	BOOL bReturn = TRUE;

	switch (IMR_RELTYPE(Data))
	{
	case IMAGE_REL_BASED_ABSOLUTE: // No action required
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_ABSOLUTE no need to process");
		#endif

		break;
	}
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
		DWORD32* Raw = (DWORD32*)(RelocationBase + IMR_RELOFFSET(Data));
		DWORD32 Backup = *Raw;

		*Raw += ImageBaseDelta;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_HIGHLOW (0x%X) -> (0x%X)", Backup, *Raw);
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
#ifdef WIN_ARM
	case IMAGE_REL_BASED_THUMB_MOV32: // arm shit
	{
		register DWORD dwInstruction;
		register DWORD dwAddress;
		register WORD wImm;
		// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
		dwInstruction = *(DWORD*)(RelocationBase + IMR_RELOFFSET(Data) + sizeof(DWORD));
		// flip the words to get the instruction as expected
		dwInstruction = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
		// sanity chack we are processing a MOV instruction...
		if ((dwInstruction & (DWORD)(0xFBF08000)) == 0xF2C00000)
		{
			// pull out the encoded 16bit value (the high portion of the address-to-relocate)
			wImm = (WORD)(dwInstruction & 0x000000FF);
			wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
			wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
			wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
			// apply the relocation to the target address
			dwAddress = ((WORD)HIWORD(ImageBaseDelta) + wImm) & 0xFFFF;
			// now create a new instruction with the same opcode and register param.
			dwInstruction = (DWORD)(dwInstruction & (DWORD)(0xFBF08F00));
			// patch in the relocated address...
			dwInstruction |= (DWORD)(dwAddress & 0x00FF);
			dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
			dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
			dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
			// now flip the instructions words and patch back into the code...
			*(DWORD *)(RelocationBase + IMR_RELOFFSET(Data) + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
		}
		break;
	}
#endif
	case IMAGE_REL_BASED_DIR64:
	{
		DWORD64* Raw = (DWORD64*)(RelocationBase + IMR_RELOFFSET(Data));
		DWORD64 Backup = *Raw;

		*Raw += ImageBaseDelta;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_DIR64 (0x%X) -> (0x%X)", Backup, *Raw);
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
		DWORD ImageBaseDelta = (DWORD)((DWORD_PTR)RemoteAddress - (DWORD_PTR)ImageNtHeaders->OptionalHeader.ImageBase);
		
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocations] VirtualAddress (0x%X)", ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		#endif

		DWORD RelocationSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocations] Relocation Size [0x%X]", RelocationSize);
		#endif

		if (RelocationSize)
		{
			PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)
				RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, BaseAddress);

			if (RelocationDirectory)
			{
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("[ProcessRelocations] RelocationDirectory (0x%X)", RelocationDirectory);
				#endif

				PVOID RelocationEnd = (PBYTE)(RelocationDirectory) + RelocationSize;

				while (RelocationDirectory < RelocationEnd)
				{
					PBYTE RelocBase = (PBYTE)(RvaToPointer(RelocationDirectory->VirtualAddress, BaseAddress));

					DWORD NumRelocs = (RelocationDirectory->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

					PWORD RelocationData = (WORD*)(RelocationDirectory + 1);

					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessRelocations] RelocationDirectory (0x%X)", RelocationDirectory);
					DebugShout("[ProcessRelocations] RelocationData (0x%X)", RelocationData);
					#endif

					for (DWORD i = 0; i < NumRelocs; ++i, ++RelocationData)
					{
						if (ProcessRelocation(ImageBaseDelta, *RelocationData, RelocBase) == FALSE)
						{
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessRelocations] Unable to process relocation [%i]", i);
							#endif
						}
					}

					RelocationDirectory = (PIMAGE_BASE_RELOCATION)(RelocationData);
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
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessRelocations] Relocations have have not been found in this executable, continuing anyway...");
			#endif

			return TRUE;
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
		return TRUE; // Success when there is no Tls Entries

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[ProcessTlsEntries] Tls Data detected!");
	#endif

	IMAGE_TLS_DIRECTORY* TlsDirectory = (IMAGE_TLS_DIRECTORY*)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, BaseAddress);
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
	if (ReadProcessMemory(m_hProcess, (const void*)TlsDirectory->AddressOfCallBacks, TLSCallbacks, sizeof(TLSCallbacks), NULL) == FALSE)
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

ULONG CRemoteLoader::GetSectionProtection(ULONG Characteristics)
{
	DWORD Result = 0;

	if (Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
	{
		Result |= PAGE_NOCACHE;
	}

	if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
	{
		if (Characteristics & IMAGE_SCN_MEM_READ)
		{
			if (Characteristics & IMAGE_SCN_MEM_WRITE)
			{
				Result |= PAGE_EXECUTE_READWRITE;
			}
			else
			{
				Result |= PAGE_EXECUTE_READ;
			}
		}
		else if (Characteristics & IMAGE_SCN_MEM_WRITE)
		{
			Result |= PAGE_EXECUTE_WRITECOPY;
		}
		else
		{
			Result |= PAGE_EXECUTE;
		}
	}
	else if (Characteristics & IMAGE_SCN_MEM_READ)
	{
		if (Characteristics & IMAGE_SCN_MEM_WRITE)
		{
			Result |= PAGE_READWRITE;
		}
		else
		{
			Result |= PAGE_READONLY;
		}
	}
	else if (Characteristics & IMAGE_SCN_MEM_WRITE)
	{
		Result |= PAGE_WRITECOPY;
	}
	else
	{
		Result |= PAGE_NOACCESS;
	}

	return Result;
}

BOOL CRemoteLoader::ProcessSection(BYTE* Name, PVOID BaseAddress, PVOID RemoteAddress, ULONG RawData, ULONG VirtualAddress, ULONG RawSize, ULONG VirtualSize, ULONG ProtectFlag)
{
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[ProcessSection] ProcessSection( %s, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X )",
					Name, BaseAddress, RemoteAddress, RawData, VirtualAddress, RawSize, VirtualSize, ProtectFlag);
	#endif

	HANDLE hProcess = GetProcess();
	if (hProcess == INVALID_HANDLE_VALUE)
		hProcess = GetCurrentProcess();

	if (WriteProcessMemory(hProcess, MakePtr(PVOID, RemoteAddress, VirtualAddress), MakePtr(PVOID, BaseAddress, RawData), RawSize, NULL) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessSection] Failed to write memory for [%s] -> [%s]", Name, LastErrorString());
		#endif
		
		return FALSE;
	}

	DWORD dwOldProtect = NULL;
	if (VirtualProtectEx(hProcess, MakePtr(PVOID, RemoteAddress, VirtualAddress), VirtualSize, ProtectFlag, &dwOldProtect) == FALSE)
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
	PIMAGE_SECTION_HEADER ImageSectionHeader =  (PIMAGE_SECTION_HEADER)(((ULONG_PTR)&ImageNtHeaders->OptionalHeader) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	for (DWORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		ULONG Protection = GetSectionProtection(ImageSectionHeader[i].Characteristics);
		if (_stricmp(".reloc", (CHAR*)ImageSectionHeader[i].Name) == 0)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessSections] Skipping \".reloc\" section.");
			#endif

			continue; // NOPE, do not process the .reloc section
		}

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

	return TRUE;
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
	
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
				GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&returnBuffer, 0, NULL);

	return returnBuffer;
}