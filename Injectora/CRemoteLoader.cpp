#include "CRemoteLoader.h"

#include <Tlhelp32.h>
#include <DbgHelp.h>

#pragma comment (lib, "DbgHelp.lib")

//
// Pube lick functions
//
void CRemoteLoader::SetProcess(HANDLE hProcess, DWORD dwProcessId)
{
	HMODULE hNtDll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	fnNTQIP = (tNTQIP)Utils::GetProcAddress(hNtDll, "NtQueryInformationProcess");
	fnNTQSI = (tNTQSI)Utils::GetProcAddress(hNtDll, "NtQuerySystemInformation");

	m_hProcess = hProcess;
	m_dwProcessId = dwProcessId;

	m_bIs64bit = GetProcessPlatform() == 2 ? true : false;
}

HMODULE CRemoteLoader::LdrpLoadDll(LPCCH Path)
{
	WCHAR WideCharModule[MAX_PATH] = { 0 };
	size_t charsConverted;
	mbstowcs_s(&charsConverted, WideCharModule, Path, MAX_PATH);
	return LdrpLoadDll(WideCharModule);
}

HMODULE CRemoteLoader::LdrpLoadDll(LPCWCH Path)
{
	if (Path == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LdrpLoadDll] Path is NULL");
		#endif
		return NULL;
	}

	FARPROC RemoteLdrpLoadDll = (FARPROC)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "LdrpLoadDll");//GetRemoteProcAddressA("ntdll.dll", "LdrLoadDll");
	if (RemoteLdrpLoadDll == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LdrpLoadDll] RemoteLdrLoadDll resolve failure");
		#endif
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LdrpLoadDll] LdrpLoadDll = 0x%IX", RemoteLdrpLoadDll);
	#endif

	NTSTATUS Status;

	UNICODE_STRING DllString1;
	ZeroMemory(&DllString1, sizeof(UNICODE_STRING));
	UNICODE_STRING DllString2;
	ZeroMemory(&DllString2, sizeof(UNICODE_STRING));
	UNICODE_STRING LdrApiDefaultExtension;
	ZeroMemory(&LdrApiDefaultExtension, sizeof(UNICODE_STRING));

	UNICODE_STRING* DllName = new UNICODE_STRING;

	PUNICODE_STRING pPath = nullptr;
	ULONG_PTR cookie = 0;
	wchar_t wBuf[255] = { 0 };

	std::wstring path(Path);
	if (path.rfind(L".dll") != std::wstring::npos)
		path.erase(path.rfind(L".dll"));

	static HMODULE hNtdll = Utils::GetLocalModuleHandle("ntdll.dll");
	static tRtlInitUnicodeString RtlInitUnicodeString = (tRtlInitUnicodeString)Utils::GetProcAddress(hNtdll, "RtlInitUnicodeString");
	static tRtlFreeUnicodeString RtlFreeUnicodeString = (tRtlFreeUnicodeString)Utils::GetProcAddress(hNtdll, "RtlFreeUnicodeString");
	static tRtlNtStatusToDosError RtlNtStatusToDosError = (tRtlNtStatusToDosError)Utils::GetProcAddress(hNtdll, "RtlNtStatusToDosError");
	static tRtlDosApplyFileIsolationRedirection_Ustr RtlDosApplyFileIsolationRedirection_Ustr = (tRtlDosApplyFileIsolationRedirection_Ustr)Utils::GetProcAddress(hNtdll, "RtlDosApplyFileIsolationRedirection_Ustr");

	RtlInitUnicodeString(DllName, path.c_str());
	RtlInitUnicodeString(&LdrApiDefaultExtension, L".DLL");

	DllString1.Buffer = wBuf;
	DllString1.Length = NULL;
	DllString1.MaximumLength = ARRAYSIZE(wBuf);

	BOOLEAN RedirectedDll = FALSE;

	/* Check if the SxS Assemblies specify another file */
	Status = RtlDosApplyFileIsolationRedirection_Ustr(TRUE, DllName, &LdrApiDefaultExtension, &DllString1, &DllString2, &DllName, NULL, NULL, NULL);
	/* Check success */
	if (NT_SUCCESS(Status))
		RedirectedDll = TRUE;

	ULONG Flags = NULL; // Maybe use flags later. Idk.
	void* flagsPtr = CommitMemory((void*)&Flags, sizeof(ULONG));

	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(size_t));

	if (m_bIs64bit)
	{
		// Backup RCX, RDX, R8 and R9 on stack
		BeginCall64();
		//
		PushInt64((unsigned __int64)RedirectedDll);
		PushInt64((unsigned __int64)NULL);
		PushInt64((unsigned __int64)flagsPtr);
		PushUNICODEStringStructure(DllName);
		PushInt64((unsigned __int64)ReturnPointerValue);
		PushInt64((unsigned __int64)TRUE);
		PushCall(CCONV_WIN64, RemoteLdrpLoadDll);
		//
		// Module Handle is located in RDX and at QWORD PTR [ReturnPointerValue].
		// Could do 'mov rax, [ReturnPointerValue]' but it takes many more opcodes to do so.
		// We could also just RPM twice on ReturnPointerValue but it's better just to get it from rdx.
		//
		// mov rax, rdx  
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x89);
		AddByteToBuffer(0xD0);
		// mov [ReturnPointerValue], rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);
		// Restore RCX, RDX, R8 and R9 from stack and return
		EndCall64();
	}
	else
	{
		PushInt(RedirectedDll);
		PushInt(NULL);
		PushInt((unsigned int)flagsPtr);
		PushUNICODEStringStructure(DllName);
		PushInt((unsigned long)ReturnPointerValue);
		PushInt(TRUE);
		PushCall(CCONV_STDCALL, RemoteLdrpLoadDll);
		//
		// Module Handle is located in [EDX].
		// To avoid calling RPM twice, we pass the [edx] into eax instead of just edx.
		//
		// mov    eax,DWORD PTR [edx]
		AddByteToBuffer(0x8B);
		AddByteToBuffer(0x02);
		// mov ptr, eax
		AddByteToBuffer(0xA3);
		AddLongToBuffer((unsigned long)ReturnPointerValue);
		// xor eax, eax
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);
		// ret 4
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x04);
		AddByteToBuffer(0x00);
	}

	if (!ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true))
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LdrpLoadDll] ExecuteRemoteThreadBuffer failed");
		#endif
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LdrpLoadDll] ExecuteRemoteThreadBuffer succeeded");
	#endif

	HMODULE RemoteModuleHandle = 0;
	if (ReadProcessMemory(m_hProcess, ReturnPointerValue, &RemoteModuleHandle, sizeof(HMODULE), NULL))
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
	}
	else
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
		if (RemoteModuleHandle == 0)
			RemoteModuleHandle = GetRemoteModuleHandleW(Path);
	}

	return RemoteModuleHandle;
}

HMODULE CRemoteLoader::LoadDependencyA(LPCCH Path)
{
	WCHAR Module[MAX_PATH] = { 0 };
	size_t charsConverted;
	mbstowcs_s(&charsConverted, Module, Path, MAX_PATH);
	return LoadDependencyW(Module);
}

HMODULE CRemoteLoader::LoadDependencyW(LPCWCH Path)
{
	if (Path == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadDependencyW] szString is NULL");
		#endif
		return NULL;
	}

	FARPROC RemoteLdrLoadDll = (FARPROC)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "LdrLoadDll");//GetRemoteProcAddressA("ntdll.dll", "LdrLoadDll");
	if (RemoteLdrLoadDll == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadDependencyW] RemoteLdrLoadDll resolve failure");
		#endif
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadDependencyW] LdrLoadDll = 0x%IX", RemoteLdrLoadDll);
	#endif

	// Make new unicode string object
	static tRtlInitUnicodeString RtlInitUnicodeString = (tRtlInitUnicodeString)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "RtlInitUnicodeString");
	UNICODE_STRING unicodePath;
	RtlInitUnicodeString(&unicodePath, Path);

	ULONG Flags = NULL; // Maybe use flags later. Idk.
	void* flagsPtr = CommitMemory((void*)&Flags, sizeof(ULONG));

	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(size_t));
	
	if (m_bIs64bit)
	{
		// Backup RCX, RDX, R8 and R9 on stack
		BeginCall64();
		//
		PushInt64(NULL);
		PushInt64((unsigned __int64)flagsPtr);
		PushUNICODEStringStructure(&unicodePath);
		PushInt64((unsigned __int64)ReturnPointerValue);
		PushCall(CCONV_WIN64, RemoteLdrLoadDll);
		//
		// Module Handle is located in RDX and at QWORD PTR [ReturnPointerValue].
		// Could do 'mov rax, [ReturnPointerValue]' but it takes many more opcodes to do so.
		// We could also just RPM twice on ReturnPointerValue but it's better just to get it from rdx.
		//
		// mov rax, rdx  
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x89);
		AddByteToBuffer(0xD0);
		// mov [ReturnPointerValue], rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);
		// Restore RCX, RDX, R8 and R9 from stack and return
		EndCall64();
	}
	else
	{
		PushInt(NULL);
		PushInt((unsigned int)flagsPtr);
		PushUNICODEStringStructure(&unicodePath);
		PushInt((unsigned long)ReturnPointerValue);
		PushCall(CCONV_STDCALL, RemoteLdrLoadDll);
		//
		// Module Handle is located in [EDX].
		// To avoid calling RPM twice, we pass the [edx] into eax instead of just edx.
		//
		// mov    eax,DWORD PTR [edx]
		AddByteToBuffer(0x8B);
		AddByteToBuffer(0x02);
		// mov ptr, eax
		AddByteToBuffer(0xA3);
		AddLongToBuffer((unsigned long)ReturnPointerValue);
		// xor eax, eax
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);
		// ret 4
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x04);
		AddByteToBuffer(0x00);
	}
	
	if (!ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true))
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] ExecuteRemoteThreadBuffer failed");
		#endif
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleByNameW] ExecuteRemoteThreadBuffer succeeded");
	#endif
	
	HMODULE RemoteModuleHandle = 0;
	if (ReadProcessMemory(m_hProcess, ReturnPointerValue, &RemoteModuleHandle, sizeof(HMODULE), NULL))
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
	}
	else
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
		if (RemoteModuleHandle == 0)
			RemoteModuleHandle = GetRemoteModuleHandleW(Path);
	}

	return RemoteModuleHandle;
}

HMODULE CRemoteLoader::LoadLibraryByPathA(LPCCH Path, ULONG Flags/*= NULL*/)
{
	WCHAR Module[MAX_PATH] = { 0 };
	size_t charsConverted;
	mbstowcs_s(&charsConverted, Module, Path, MAX_PATH);
	return LoadLibraryByPathW(Module, Flags);
}

HMODULE CRemoteLoader::LoadLibraryByPathW(LPCWCH Path, ULONG Flags/*= NULL*/)
{
	if (Path == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] szString is NULL");
		#endif
		return NULL;
	}

	FARPROC RemoteLdrLoadDll = (FARPROC)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "LdrLoadDll"); //GetRemoteProcAddressA("ntdll.dll", "LdrLoadDll");
	if (RemoteLdrLoadDll == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] RemoteLdrLoadDll resolve failure");
		#endif
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryByPathW] LdrLoadDll = 0x%IX", RemoteLdrLoadDll);
	#endif

	// Make new unicode string object
	static tRtlInitUnicodeString RtlInitUnicodeString = (tRtlInitUnicodeString)Utils::GetProcAddress(Utils::GetLocalModuleHandle("ntdll.dll"), "RtlInitUnicodeString");
	UNICODE_STRING unicodePath;
	RtlInitUnicodeString(&unicodePath, Path);

	void* flagsPtr = CommitMemory((void*)&Flags, sizeof(ULONG));

	void* ReturnPointerValue = RemoteAllocateMemory(sizeof(size_t));
	
	if (m_bIs64bit)
	{
		// Backup RCX, RDX, R8 and R9 on stack
		BeginCall64();
		//
		PushInt64(NULL);
		PushInt64((unsigned __int64)flagsPtr);
		PushUNICODEStringStructure(&unicodePath);
		PushInt64((unsigned __int64)ReturnPointerValue);
		PushCall(CCONV_WIN64, RemoteLdrLoadDll);
		//
		// Module Handle is located in RDX and at QWORD PTR [ReturnPointerValue].
		// Could do 'mov rax, [ReturnPointerValue]' but it takes many more opcodes to do so.
		// We could also just RPM twice on ReturnPointerValue but it's better just to get it from rdx.
		//
		// mov rax, rdx  
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x89);
		AddByteToBuffer(0xD0);
		// mov [ReturnPointerValue], rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);
		// Restore RCX, RDX, R8 and R9 from stack and return
		EndCall64();
	}
	else
	{
		PushInt(NULL);
		PushInt((unsigned int)flagsPtr);
		PushUNICODEStringStructure(&unicodePath);
		PushInt((unsigned long)ReturnPointerValue);
		PushCall(CCONV_STDCALL, RemoteLdrLoadDll);
		//
		// Module Handle is located in [EDX].
		// To avoid calling RPM twice, we pass the [edx] into eax instead of just edx.
		//
		// mov    eax,DWORD PTR [edx]
		AddByteToBuffer(0x8B);
		AddByteToBuffer(0x02);
		// mov ptr, eax
		AddByteToBuffer(0xA3);
		AddLongToBuffer((unsigned long)ReturnPointerValue);
		// xor eax, eax
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);	
		// ret 4
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x04);
		AddByteToBuffer(0x00);
	}
	
	if (ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer) == false)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryByPathW] ExecuteRemoteThreadBuffer failed");
		#endif
	
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
	
		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleByNameW] ExecuteRemoteThreadBuffer succeeded");
	#endif
	
	HMODULE RemoteModuleHandle = 0;
	if (ReadProcessMemory(m_hProcess, ReturnPointerValue, &RemoteModuleHandle, sizeof(HMODULE), NULL))
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
	}
	else
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
		if (RemoteModuleHandle == 0)
			RemoteModuleHandle = GetRemoteModuleHandleW(Path);
	}

	return RemoteModuleHandle;
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
	return LoadLibraryByPathIntoMemoryA(PathAnsi, PEHeader);
}

HMODULE CRemoteLoader::LoadLibraryFromMemory(PVOID BaseAddress, DWORD SizeOfModule, BOOL PEHeader)
{
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] BaseAddress (0x%IX) - SizeOfModule (0x%X)", BaseAddress, SizeOfModule);
	#endif

	IMAGE_NT_HEADERS* ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Invalid Image: No IMAGE_NT_HEADERS");
		#endif
		return NULL;
	}

	if (ImageNtHeaders->FileHeader.NumberOfSections == 0)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Invalid Image: No Sections");
		#endif
		return NULL;
	}

	if ( m_bIs64bit)
	{
		//
		// Create Remote Procedure Call environment. No need for this in 32 bit
		//
		DWORD err = CreateRPCEnvironment();
		if (err != ERROR_SUCCESS)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadLibraryFromMemory] CreateRPCEnvironment failed. Error 0x%X", err);
			#endif
			return NULL;
		}

		//
		// Create activation context for the module we're injecting. Not needed for x86 modules.
		//
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Creating Activation Context!");
		#endif

		if (!CreateActx(BaseAddress))
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadLibraryFromMemory] Failed to obtain embedded resource! Continuing anyway without Activation Context...");
			#endif
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadLibraryFromMemory] Createed Activation Context successfully!");
			#endif
		}
	}

	// We do not trust the value of hdr.OptionalHeader.SizeOfImage so we calculate our own SizeOfImage.
	// This is the size of the continuous memory block that can hold the headers and all sections.
	//
	size_t rva_low = (!PEHeader) ? ((size_t)-1) : 0;
	size_t rva_high = 0;
	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (size_t i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (!ImageSectionHeader[i].Misc.VirtualSize)
			continue;
		if (ImageSectionHeader[i].VirtualAddress < rva_low)
			rva_low = ImageSectionHeader[i].VirtualAddress;
		if ((ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].Misc.VirtualSize) > rva_high)
			rva_high = ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].Misc.VirtualSize;
	}

	// Calculated Image Size
	//
	size_t ImageSize = rva_high - rva_low;

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Calculated size (0x%IX)", ImageSize);
	#endif

	if ((ImageNtHeaders->OptionalHeader.ImageBase % 4096) != 0)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Invalid Image: Not Page Aligned");
		#endif
		return NULL;
	}

	if (ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size && ::ImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, NULL))
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] This method is not supported for Managed executables!");
		#endif
		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Good, no COM/CLR data found!");
	#endif

	// SizeOfImage NOT the same as module size MOTHERFUCKER
	// http://www.youtube.com/watch?v=pele5vptVgc
	void* AllocatedRemoteMemory = RemoteAllocateMemory(ImageSize);
	if (AllocatedRemoteMemory == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to allocate remote memory for module!");
		#endif
		return NULL;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Allocated remote module at [0x%IX]!", AllocatedRemoteMemory);
	DebugShout("[LoadLibraryFromMemory] Processing Import Tables....\n");
	#endif

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
	DebugShout("[LoadLibraryFromMemory] Processing Relocations....\n");
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
	DebugShout("[LoadLibraryFromMemory] Processing Sections!");
	#endif

	if (ProcessSections(BaseAddress, AllocatedRemoteMemory, PEHeader) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to process sections!");
		#endif
	}

	if (m_bIs64bit && PEHeader)
		EnableExceptions(BaseAddress, AllocatedRemoteMemory, ImageSize);


	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadLibraryFromMemory] Processed sections!");
	DebugShout("[LoadLibraryFromMemory] Processing TLS Callback Entries!");
	#endif
	
	if (ProcessTlsEntries(BaseAddress, AllocatedRemoteMemory) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadModuleFromMemory] ProcessTlsEntries Failed!");
		#endif
		// we can also choose to continue here, but we wont cause unsafe
		return NULL;
	}
	
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleFromMemory] Processed Tls Entries!");
	#endif

	// Security cookie if needed
	InitializeCookie(BaseAddress, AllocatedRemoteMemory);

	if (ImageNtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		FARPROC DllEntryPoint = MakePtr(FARPROC, AllocatedRemoteMemory, ImageNtHeaders->OptionalHeader.AddressOfEntryPoint);
		
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadModuleFromMemory] DllEntrypoint = 0x%IX", DllEntryPoint);
		#endif

		if (CallEntryPoint(AllocatedRemoteMemory, DllEntryPoint) == false)
		{	
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadModuleFromMemory] Failed to execute remote thread buffer");
			#endif
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadModuleFromMemory] Executed the remote thread buffer successfully [0x%IX]", DllEntryPoint);
			#endif
		}
	}	
	else
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadModuleFromMemory] AddressOfEntryPoint is NULL");
		#endif
	}
	

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[LoadModuleFromMemory] Returning Pointer (0x%IX)", AllocatedRemoteMemory);
	#endif

	if (m_bIs64bit)
	{
		TerminateWorkerThread();
	}
	
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

						//wchar_t wcsFullDllName[MAX_PATH] = { 0 };
						//char strFullDllName[MAX_PATH] = { 0 };
						//if (lstEntry.FullDllName.Length > 0)
						//{
						//	dwBytesRead = 0;
						//	if (ReadProcessMemory(m_hProcess, (LPCVOID)lstEntry.FullDllName.Buffer, &wcsFullDllName, lstEntry.FullDllName.Length, &dwBytesRead))
						//	{
						//		size_t bytesCopied = 0;
						//		wcstombs_s(&bytesCopied, strFullDllName, wcsFullDllName, MAX_PATH);
						//	}
						//}

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

BOOL CRemoteLoader::CallEntryPoint(void* BaseAddress, FARPROC Entrypoint)
{
	if (m_bIs64bit)
	{
		// ActivateActCtx 
		if (m_pAContext)
		{
			size_t rsp_dif =  0x28;
			rsp_dif = Utils::Align(rsp_dif, 0x10);
			// sub  rsp, (rsp_dif + 8)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xEC);
			AddByteToBuffer((unsigned char)(rsp_dif + 8));
			// >>>
			// >>>
			// mov  rax, m_pAContext
			AddByteToBuffer(0x48); 
			AddByteToBuffer(0xB8);
			AddLong64ToBuffer((size_t)m_pAContext);
			// mov  rax, [rax]
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x8B); 
			AddByteToBuffer(0x00);
			// mov  rcx, rax -> first parameter
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x89);
			AddByteToBuffer(0xC1);
			// mov  rdx, (m_pAContext + sizeof(HANDLE)) -> second parameter
			LoadParam64((size_t)m_pAContext + sizeof(HANDLE), PARAM_INDEX_RDX);	
			// mov  r13, calladdress
			AddByteToBuffer(0x49);
			AddByteToBuffer(0xBD);
			AddLong64ToBuffer((size_t)ActivateActCtx);
			// call r13
			AddByteToBuffer(0x41);
			AddByteToBuffer(0xFF);
			AddByteToBuffer(0xD5);
			// >>>
			// >>>
			// add rsp, (rsp_dif + 8)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xC4);
			AddByteToBuffer((unsigned char)(rsp_dif + 8));
		}

		/* Call the actual entry point */
		PushInt64((unsigned __int64)BaseAddress);
		PushInt64(DLL_PROCESS_ATTACH);
		PushInt64(0x00);
		PushCall(CCONV_WIN64, Entrypoint);

		// DeactivateActCtx
		if (m_pAContext)
		{
			size_t rsp_dif = 0x28;
			rsp_dif = Utils::Align(rsp_dif, 0x10);
			// sub  rsp, (rsp_dif + 8)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xEC);
			AddByteToBuffer((unsigned char)(rsp_dif + 8));
			// >>>
			// >>>
			// mov  rax, m_pAContext + sizeof(HANDLE)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0xB8);
			AddLong64ToBuffer((size_t)m_pAContext + sizeof(HANDLE));
			// mov  rax, [rax]
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x8B);
			AddByteToBuffer(0x00);
			// mov  rcx, 0 -> first parameter
			LoadParam64(0, PARAM_INDEX_RCX);
			// mov  rdx, rax
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x89);
			AddByteToBuffer(0xC2);
			// mov  r13, calladdress
			AddByteToBuffer(0x49);
			AddByteToBuffer(0xBD);
			AddLong64ToBuffer((size_t)DeactivateActCtx);
			// call r13
			AddByteToBuffer(0x41);
			AddByteToBuffer(0xFF);
			AddByteToBuffer(0xD5);
			// >>>
			// >>>
			// add rsp, (rsp_dif + 8)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xC4);
			AddByteToBuffer((unsigned char)(rsp_dif + 8));		
		}

		// Signal wait event
		SaveRetValAndSignalEvent();
		// Restore registers from stack and return
		EndCall64();

		size_t result;
		if (ExecuteInWorkerThread(m_CurrentRemoteThreadBuffer, result) != ERROR_SUCCESS)
		{
			TerminateWorkerThread();
			DestroyRemoteThreadBuffer();
			return FALSE;
		}

		return TRUE;
	}
	
	// x86 injection
	PushInt((INT)BaseAddress);
	PushInt(DLL_PROCESS_ATTACH);
	PushInt(0);
	PushCall(CCONV_STDCALL, Entrypoint);
	// Zero eax and return
	// xor eax, eax
	AddByteToBuffer(0x33);
	AddByteToBuffer(0xC0);
	// ret 4
	AddByteToBuffer(0xC2);
	AddByteToBuffer(0x04);
	AddByteToBuffer(0x00);

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("\nCallEntryPoint [0x%IX]:", Entrypoint);
	#endif 

	return ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true);
}

bool CRemoteLoader::CreateActx(PVOID BaseAddress)
{
	if (CreateTempManifestFileFromMemory(BaseAddress, 2))
	{
		bool ret = CreateActxFromManifest(m_tempManifest);
		remove(m_tempManifest);
		ZeroMemory(m_tempManifest, MAX_PATH);
		return ret;
	}
	else
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[LoadLibraryFromMemory] Failed to get temp manifest from memory using Resource ID 2. Trying ID 1...");
		#endif
		//if (CreateTempManifestFileFromMemory(BaseAddress, 1))
		//{
		//	bool ret = CreateActxFromManifest(m_tempManifest);
		//	remove(m_tempManifest);
		//	ZeroMemory(m_tempManifest, MAX_PATH);
		//	return ret;
		//}
		//else
		return false;
	}
}

bool CRemoteLoader::CreateTempManifestFileFromMemory(PVOID BaseAddress, DWORD ResourceId)
{
	void* ManifestResource = NULL;
	DWORD ManifestSize = GetEmbeddedManifestResourceFromMemory(BaseAddress, ResourceId, &ManifestResource);
	if (ManifestResource)
	{
		if (!SetBaseDirectory())
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[CreateTempManifestFileFromMemory] Failed to get base directory to create temp manifest in!");
			#endif
			return false;
		}

		strcpy_s(m_tempManifest, m_baseDir);
		char randomFilename[MAX_PATH];
		sprintf_s(randomFilename, "%IX", GetTickCount64());
		strcat_s(m_tempManifest, randomFilename);

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[CreateTempManifestFileFromMemory] Temp file: %s", m_tempManifest);
		#endif

		FILE* f;
		errno_t err = fopen_s(&f, m_tempManifest, "w");
		if (f && err == NULL)
			fwrite(ManifestResource, sizeof(char), ManifestSize, f);
		fclose(f);

		return true;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[CreateTempManifestFileFromMemory] Failed to obtain embedded Manifest resource from memory!");
	#endif

	return false;
}

DWORD CRemoteLoader::GetEmbeddedManifestResourceFromMemory(PVOID BaseAddress, DWORD ResourceId, void** Resource)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;

	DWORD ResourceSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	if (ResourceSize)
	{
		PIMAGE_RESOURCE_DIRECTORY RootResourceDir = (PIMAGE_RESOURCE_DIRECTORY)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, BaseAddress);
		if (RootResourceDir)
		{
			const IMAGE_RESOURCE_DIR_STRING_U* dir_string = 0;

			// 
			// enumerate all types
			// 
			for (WORD i = 0; i < RootResourceDir->NumberOfIdEntries + RootResourceDir->NumberOfNamedEntries; i++)
			{
				PIMAGE_RESOURCE_DIRECTORY_ENTRY EntryType = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(RootResourceDir + 1 + i);
				if ((EntryType->OffsetToDirectory) >= ResourceSize)
					return NULL;

				PIMAGE_RESOURCE_DIRECTORY ResType = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)RootResourceDir + (EntryType->OffsetToDirectory));

				if (EntryType->NameIsString) {
					dir_string = reinterpret_cast<const IMAGE_RESOURCE_DIR_STRING_U*>((PBYTE)RootResourceDir + EntryType->NameOffset);
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[GetEmbeddedManifestResourceFromMemory] Resource Id: %S", &dir_string->NameString[0]);
					#endif
				} else {
					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[GetEmbeddedManifestResourceFromMemory] Resource Id: %i", EntryType->Id);
					#endif
				}

				//
				// enumerate all names
				//
				for (WORD j = 0; j < ResType->NumberOfIdEntries + ResType->NumberOfNamedEntries; j++)
				{
					PIMAGE_RESOURCE_DIRECTORY_ENTRY EntryIdentifier = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(ResType + 1 + j);
					if ((EntryIdentifier->OffsetToDirectory) >= ResourceSize)
						return NULL;

					// Check if the resource ID is what we're looking for or not
					if (EntryIdentifier->Id != ResourceId)
						continue;

					PIMAGE_RESOURCE_DIRECTORY ResIdentifier = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)RootResourceDir + (EntryIdentifier->OffsetToDirectory));

					if (EntryIdentifier->NameIsString) {
						dir_string = reinterpret_cast<const IMAGE_RESOURCE_DIR_STRING_U*>((PBYTE)RootResourceDir + EntryIdentifier->NameOffset);
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[GetEmbeddedManifestResourceFromMemory] Resource Id: %S", &dir_string->NameString[0]);
						#endif
					} else {
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[GetEmbeddedManifestResourceFromMemory] Resource Id: %i", EntryIdentifier->Id);
						#endif
					}

					//
					// enumerate all languages 
					// now we have access to the offsets of the data
					//
					for (WORD k = 0; k < ResIdentifier->NumberOfIdEntries + ResIdentifier->NumberOfNamedEntries; k++)
					{
						PIMAGE_RESOURCE_DIRECTORY_ENTRY DataLangEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(ResIdentifier + 1 + k);
						if ((DataLangEntry->OffsetToDirectory) >= ResourceSize)
							return FALSE;

						PIMAGE_RESOURCE_DATA_ENTRY pData = (PIMAGE_RESOURCE_DATA_ENTRY)((PBYTE)RootResourceDir + (DataLangEntry->OffsetToDirectory));

						if (DataLangEntry->NameIsString) {
							dir_string = reinterpret_cast<const IMAGE_RESOURCE_DIR_STRING_U*>((PBYTE)RootResourceDir + DataLangEntry->NameOffset);
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[GetEmbeddedManifestResourceFromMemory] Resource Id: %S", &dir_string->NameString[0]);
							#endif
						} else {
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[GetEmbeddedManifestResourceFromMemory] Resource Id: %i", DataLangEntry->Id);
							#endif
						}
						
						if (pData->Size == 0)
							continue;

						void* ResourceData = RvaToPointer(pData->OffsetToData, BaseAddress);
						if (ResourceData && (DWORD64)ResourceData == (DWORD64)-1)
							continue;	// empty or encrypted resource?

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[GetEmbeddedManifestResourceFromMemory] Resource Data: 0x%IX", ResourceData);
						#endif

						*Resource = ResourceData;

						return pData->Size;
					}
				}
			}
		}
	}
	// Empty or no resource directory
	return NULL;
}

// Set custom exception handler to bypass SafeSEH under DEP 
NTSTATUS CRemoteLoader::EnableExceptions(PVOID BaseAddress, PVOID RemoteAddress, size_t ImageSize)
{
#ifdef _M_AMD64
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;

	size_t size = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

	PIMAGE_RUNTIME_FUNCTION_ENTRY pExpTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, BaseAddress);
	if (pExpTable)
	{
		size_t result = 0;

		size_t ExpTableAddr = (size_t)pExpTable - (size_t)BaseAddress + (size_t)RemoteAddress;

		BeginCall64();

		PushInt64(ExpTableAddr);
		PushInt64(size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
		PushInt64((size_t)RemoteAddress);
		PushCall(CCONV_WIN64, (FARPROC)RtlAddFunctionTable);

		SaveRetValAndSignalEvent();

		EndCall64();

		if (ExecuteInWorkerThread(m_CurrentRemoteThreadBuffer, result) != ERROR_SUCCESS)
			return false;
		
		return (CreateVEH((size_t)RemoteAddress, ImageSize) == ERROR_SUCCESS);
	}
	else
		return false;
#else
	return true;
#endif
}

DWORD CRemoteLoader::CreateVEH(size_t RemoteAddress /*= 0*/, size_t ImageSize /*= 0*/)
{
	return GetLastError();
}

// Calculate and set security cookie
bool CRemoteLoader::InitializeCookie(PVOID BaseAddress, PVOID RemoteAddress)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = ToNts(BaseAddress);
	if (ImageNtHeaders == NULL)
		return FALSE;

	PIMAGE_LOAD_CONFIG_DIRECTORY pLC = (PIMAGE_LOAD_CONFIG_DIRECTORY)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, BaseAddress);

	//
	// Cookie generation based on MSVC++ compiler
	//
	if (pLC && pLC->SecurityCookie)
	{
		FILETIME systime = { 0 };
		LARGE_INTEGER PerformanceCount = { { 0 } };
		uintptr_t cookie = 0;

		GetSystemTimeAsFileTime(&systime);
		QueryPerformanceCounter(&PerformanceCount);

		cookie = m_dwProcessId ^ m_dwWorkerThreadId ^ reinterpret_cast<uintptr_t>(&cookie);

		#ifdef _M_AMD64
        cookie ^= *reinterpret_cast<unsigned __int64*>(&systime);
        cookie ^= (PerformanceCount.QuadPart << 32) ^ PerformanceCount.QuadPart;
        cookie &= 0xFFFFFFFFFFFF;

        if (cookie == 0x2B992DDFA232)
            cookie++;
		#else

        cookie ^= systime.dwHighDateTime ^ systime.dwLowDateTime;
        cookie ^= PerformanceCount.LowPart;
        cookie ^= PerformanceCount.HighPart;

        if (cookie == 0xBB40E64E)
            cookie++;
        else if (!(cookie & 0xFFFF0000))
            cookie |= (cookie | 0x4711) << 16;
		#endif

		size_t RemoteCookieAddr = (size_t)pLC->SecurityCookie - (size_t)BaseAddress + (size_t)RemoteAddress;

		if (!WriteProcessMemory(m_hProcess, (void*)RemoteCookieAddr, (const void*)cookie, sizeof(uintptr_t), NULL))
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[InitializeCookie] Failed to write generated security cookie!");
			#endif
			return false;
		}

		return true;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[InitializeCookie] No security cookie for module. Continuing.");
	#endif

	return true;
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
				{
					std::string strDll = ModuleName;
					std::wstring strBaseDll = L"";

					strBaseDll.assign(strDll.begin(), strDll.end());
					ResolvePath(strBaseDll, EnsureFullPath);

					if (m_bIs64bit)
						ModuleBase = LoadDependencyW(strBaseDll.c_str());
					else
						ModuleBase = LoadLibraryByPathIntoMemoryW(strBaseDll.c_str(), TRUE); // LoadDependencyW(strBaseDll.c_str());
 					if (ModuleBase == NULL)
					{
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessImportTable] Failed to obtain module handle [%s]", ModuleName);
						#endif
						continue;
					}
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

					bool bSnapByOrdinal = m_bIs64bit ? ((ImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0) : ((ImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32) != 0);
					if (bSnapByOrdinal)
					{
						SHORT Ordinal = (SHORT)(ImageThunkData->u1.Ordinal & 0xffff);

						FunctionAddress = (FARPROC)GetDependencyProcAddressA(ModuleBase, (const char*)Ordinal);

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
						DebugShout("[ProcessImportTable] Processed (%s -> %i) -> (0x%IX)", ModuleName, Ordinal, FunctionAddress);
						#endif
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData, BaseAddress);
						char* NameOfImport = (char*)ImageImportByName->Name;

						FunctionAddress = (FARPROC)GetDependencyProcAddressA(ModuleBase, NameOfImport);

						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessImportTable] Processed (%s -> %s) -> (0x%IX)", ModuleName, NameOfImport, FunctionAddress);
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
				{
					std::string strDll = ModuleName;
					std::wstring strBaseDll = L"";

					strBaseDll.assign(strDll.begin(), strDll.end());
					ResolvePath(strBaseDll, EnsureFullPath);

					if (m_bIs64bit)
						ModuleBase = LoadDependencyW(strBaseDll.c_str());
					else
						ModuleBase = LoadLibraryByPathIntoMemoryW(strBaseDll.c_str(), TRUE); //LoadDependencyW(strBaseDll.c_str());
					if (ModuleBase == NULL)
					{
						#ifdef DEBUG_MESSAGES_ENABLED
						DebugShout("[ProcessDelayedImportTable] Failed to obtain module handle [%s]", ModuleName);
						#endif
						continue;
					}
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

						FunctionAddress = (FARPROC)GetDependencyProcAddressA(ModuleBase, (const char*)Ordinal); // Utils::GetProcAddress
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
						DebugShout("[ProcessDelayedImportTable] Processed (%s -> %i) -> (0x%IX)", ModuleName, Ordinal, FunctionAddress);
						#endif
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPointer(*(DWORD*)ImageThunkData, BaseAddress);

						FunctionAddress = (FARPROC)GetDependencyProcAddressA(ModuleBase, (LPCCH)ImageImportByName->Name); // Utils::GetProcAddress
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
						DebugShout("[ProcessDelayedImportTable] Processed (%s -> %s) -> (0x%IX)", ModuleName, (PCHAR)ImageImportByName->Name, FunctionAddress);
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

FARPROC CRemoteLoader::GetRemoteProcAddressW(LPCWCH Module, LPCWCH procName)
{
	char ModuleAnsi[MAX_PATH] = { 0 };
	size_t charsConverted;
	wcstombs_s(&charsConverted, ModuleAnsi, Module, MAX_PATH);

	char ProcNameAnsi[MAX_PATH];
	wcstombs_s(&charsConverted, ProcNameAnsi, procName, MAX_PATH);

	return GetRemoteProcAddressA(ModuleAnsi, ProcNameAnsi);
}

FARPROC CRemoteLoader::GetDependencyProcAddressW(HMODULE ModuleBase, LPCWCH procName)
{
	char ProcAnsi[MAX_PATH];
	size_t charsConverted;
	wcstombs_s(&charsConverted, ProcAnsi, procName, MAX_PATH);
	return GetDependencyProcAddressA(ModuleBase, ProcAnsi);
}

FARPROC CRemoteLoader::GetDependencyProcAddressA(HMODULE ModuleBase, LPCCH proc_name)
{
	void* modb = (void*)ModuleBase;

	IMAGE_DOS_HEADER hdrDos = { 0 };
	IMAGE_NT_HEADERS hdrNt32 = { 0 };
	IMAGE_EXPORT_DIRECTORY* expData = { 0 };
	void* pFunc = NULL;

	SIZE_T dwRead = 0;
	ReadProcessMemory(m_hProcess, (BYTE*)modb, &hdrDos, sizeof(IMAGE_DOS_HEADER), &dwRead);
	if (hdrDos.e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	ReadProcessMemory(m_hProcess, (BYTE*)modb + hdrDos.e_lfanew, &hdrNt32, sizeof(IMAGE_NT_HEADERS), &dwRead);
	if (hdrNt32.Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	size_t expBase = hdrNt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	// Exports are present
	if (expBase)
	{
		DWORD expSize = hdrNt32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		expData = (IMAGE_EXPORT_DIRECTORY*)malloc(expSize);
		ReadProcessMemory(m_hProcess, (BYTE*)modb + expBase, expData, expSize, &dwRead);

		WORD  *pAddressOfOrds  = (WORD*) (expData->AddressOfNameOrdinals + (size_t)expData - expBase);
		DWORD *pAddressOfNames = (DWORD*)(expData->AddressOfNames + (size_t)expData - expBase);
		DWORD *pAddressOfFuncs = (DWORD*)(expData->AddressOfFunctions + (size_t)expData - expBase);

		for (DWORD i = 0; i < expData->NumberOfFunctions; ++i)
		{
			WORD OrdIndex = 0xFFFF;
			char *pName = NULL;
			// Find by index
			if ((size_t)proc_name <= 0xFFFF)
				OrdIndex = (WORD)i;
			// Find by name
			else if ((size_t)proc_name > 0xFFFF && i < expData->NumberOfNames)
			{
				pName = (char*)(pAddressOfNames[i] + (size_t)expData - expBase);
				OrdIndex = (WORD)pAddressOfOrds[i];
			}
			else
				return 0;

			if (((size_t)proc_name <= 0xFFFF && (WORD)proc_name == (OrdIndex + expData->Base)) || ((size_t)proc_name > 0xFFFF && strcmp(pName, proc_name) == 0))
			{
				pFunc = (void*)((size_t)modb + pAddressOfFuncs[OrdIndex]);
				// Check forwarded export
				if ((size_t)pFunc >= (size_t)modb + expBase && (size_t)pFunc <= (size_t)modb + expBase + expSize)
				{
					char forwardStr[255] = { 0 };
					ReadProcessMemory(m_hProcess, pFunc, forwardStr, sizeof(forwardStr), &dwRead);

					std::string chainExp(forwardStr);

					std::string strDll = chainExp.substr(0, chainExp.find(".")) + ".dll";
					std::string strName = chainExp.substr(chainExp.find(".") + 1, strName.npos);

					HMODULE hChainMod = GetRemoteModuleHandleA(strDll.c_str());
					if (hChainMod == NULL)
						hChainMod = LoadDependencyA(strDll.c_str());

					// Import by ordinal
					if (strName.find("#") == 0)
						return GetDependencyProcAddressA(hChainMod, (const char*)atoi(strName.c_str() + 1));	
					else // Import by name
						return GetDependencyProcAddressA(hChainMod, strName.c_str());
				}

				break;
			}
		}
		// Free allocated data
		free(expData);
	}

	return (FARPROC)pFunc;
}

FARPROC	CRemoteLoader::GetRemoteProcAddressW(LPCWCH Module, SHORT procOrdinal)
{
	char ModuleAnsi[MAX_PATH];
	size_t charsConverted;
	wcstombs_s(&charsConverted, ModuleAnsi, Module, MAX_PATH);

	return GetRemoteProcAddressA(ModuleAnsi, procOrdinal);
}

FARPROC CRemoteLoader::GetRemoteProcAddressA(LPCCH Module, LPCCH procName)
{
	HMODULE hKernel32 = Utils::GetLocalModuleHandle("Kernel32.dll");
	if (hKernel32 == NULL) 
		return NULL;

	size_t GetProcAddressOffset = (size_t)GetProcAddress - (size_t)hKernel32;

	HMODULE hRemoteKernel32 = GetRemoteModuleHandleA("Kernel32.dll");
	if (hRemoteKernel32 == NULL) 
		return NULL;

	HMODULE hRemoteModule = GetRemoteModuleHandleA(Module);
	if (hRemoteModule == NULL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[GetRemoteProcAddressA] Failed to obtain module handle [%s]", Module);
		#endif
		return NULL;
	}

	PVOID ReturnPointerValue = RemoteAllocateMemory(sizeof(size_t));

	if (m_bIs64bit)
	{
		// Backup RCX, RDX, R8, and R9 on stack
		BeginCall64();

		PushInt64((unsigned __int64)hRemoteModule);
		PushANSIString((PCHAR)procName);
		PushCall(CCONV_WIN64, (FARPROC)((size_t)hRemoteKernel32 + (size_t)GetProcAddressOffset));

		// mov [ReturnPointerValue], rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xA3);
		AddLong64ToBuffer((unsigned __int64)ReturnPointerValue);

		SaveRetValAndSignalEvent();

		// Restore RCX, RDX, R8, and R9 from stack and return
		EndCall64();
	}
	else
	{
		PushInt((unsigned int)hRemoteModule);
		PushANSIString((PCHAR)procName);
		PushCall(CCONV_STDCALL, (FARPROC)((size_t)hRemoteKernel32 + (size_t)GetProcAddressOffset));

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

	if (m_bIs64bit)
	{
		size_t result;
		if (ExecuteInWorkerThread(m_CurrentRemoteThreadBuffer, result) != ERROR_SUCCESS)
		{
			RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
			return NULL;
		}
	}
	else
	{
		if (!ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true))
		{
			RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
			return NULL;
		}
	}

	size_t ProcAddressRemote = 0;
	if (ReadProcessMemory(m_hProcess, ReturnPointerValue, &ProcAddressRemote, sizeof(size_t), NULL) == TRUE)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
		return (FARPROC)ProcAddressRemote;
	}

	RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));

	return NULL;
}

FARPROC CRemoteLoader::GetRemoteProcAddressA(LPCCH Module, SHORT procOrdinal)
{
	HMODULE hKernel32 = Utils::GetLocalModuleHandle("Kernel32.dll");
	if (hKernel32 == NULL)
		return NULL;

	size_t GetProcAddressOffset = (size_t)GetProcAddress - (size_t)hKernel32;

	HMODULE hRemoteKernel32 = GetRemoteModuleHandleA("Kernel32.dll");
	if (hRemoteKernel32 == NULL)
		return NULL;

	HMODULE hRemoteModule = GetRemoteModuleHandleA(Module);
	if (hRemoteModule == NULL)
	{
		std::string strDll = Module;
		std::wstring strBaseDll = L"";

		strBaseDll.assign(strDll.begin(), strDll.end());
		ResolvePath(strBaseDll, EnsureFullPath);

		hRemoteModule = LoadDependencyW(strBaseDll.c_str());
		if (hRemoteModule == NULL)
			return NULL;
	}

	PVOID ReturnPointerValue = RemoteAllocateMemory(sizeof(size_t));

	PushInt((INT)hRemoteModule);
	PushInt((INT)procOrdinal);
	PushCall(CCONV_STDCALL, (FARPROC)((size_t)hRemoteKernel32 + (size_t)GetProcAddressOffset));

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

	if (!ExecuteRemoteThreadBuffer(m_CurrentRemoteThreadBuffer, true))
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(DWORD));
		return NULL;
	}

	size_t ProcAddressRemote = 0;
	if (ReadProcessMemory(m_hProcess, ReturnPointerValue, &ProcAddressRemote, sizeof(DWORD), NULL) == TRUE)
	{
		RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));
		return (FARPROC)ProcAddressRemote;
	}

	RemoteFreeMemory(ReturnPointerValue, sizeof(size_t));

	return NULL;
}

BOOL CRemoteLoader::ProcessRelocation(size_t ImageBaseDelta, WORD Data, PBYTE RelocationBase)
{
	BOOL bReturn = TRUE;
	switch (IMR_RELTYPE(Data))
	{
	case IMAGE_REL_BASED_HIGH:
	{
		SHORT* Raw = (SHORT*)(RelocationBase + IMR_RELOFFSET(Data));
		SHORT Backup = *Raw;

		*Raw += (ULONG)HIWORD(ImageBaseDelta);

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_HIGH (0x%IX) -> (0x%IX)", Backup, *Raw);
		#endif

		break;
	}
	case IMAGE_REL_BASED_LOW:
	{
		SHORT* Raw = (SHORT*)(RelocationBase + IMR_RELOFFSET(Data));
		SHORT Backup = *Raw;

		*Raw += (ULONG)LOWORD(ImageBaseDelta);

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_LOW (0x%IX) -> (0x%X)", Backup, *Raw);
		#endif

		break;
	}
	case IMAGE_REL_BASED_HIGHLOW:
	{
		size_t* Raw = (size_t*)(RelocationBase + IMR_RELOFFSET(Data));
		size_t Backup = *Raw;

		*Raw += (size_t)ImageBaseDelta;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_HIGHLOW (0x%IX) -> (0x%X)", Backup, *Raw);
		#endif

		break;
	}
	case IMAGE_REL_BASED_DIR64:
	{
		DWORD_PTR UNALIGNED* Raw = (DWORD_PTR UNALIGNED*)(RelocationBase + IMR_RELOFFSET(Data));
		DWORD_PTR UNALIGNED Backup = *Raw;

		*Raw += ImageBaseDelta;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocation] IMAGE_REL_BASED_DIR64 (0x%IX) -> (0x%IX)", Backup, *Raw);
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
		DebugShout("[ProcessRelocation] UNKNOWN RELOCATION (0x%IX)", IMR_RELTYPE(Data));
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
		DebugShout("[ProcessRelocations] Relocations have been stripped from this executable, continuing..");
		#endif
		return TRUE;
	}
	else
	{
		size_t ImageBaseDelta = MakeDelta(size_t, RemoteAddress, ImageNtHeaders->OptionalHeader.ImageBase);

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocations] VirtualAddress (0x%IX)",ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		#endif

		DWORD RelocationSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessRelocations] Relocation Size [0x%IX]", RelocationSize);
		#endif

		if (RelocationSize)
		{
			PIMAGE_BASE_RELOCATION RelocationDirectory = (PIMAGE_BASE_RELOCATION)RvaToPointer(ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, BaseAddress);
			if (RelocationDirectory)
			{
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("[ProcessRelocations] RelocationDirectory (0x%IX)", RelocationDirectory);
				#endif

				PVOID RelocationEnd = reinterpret_cast<PBYTE>(RelocationDirectory) + RelocationSize;

				while (RelocationDirectory < RelocationEnd)
				{
					PBYTE RelocBase = static_cast<PBYTE>(RvaToPointer(RelocationDirectory->VirtualAddress, BaseAddress));

					DWORD NumRelocs = (RelocationDirectory->SizeOfBlock - 8) >> 1;

					PWORD RelocationData = reinterpret_cast<PWORD>(RelocationDirectory + 1);

					#ifdef DEBUG_MESSAGES_ENABLED
					DebugShout("[ProcessRelocations] RelocationData (0x%IX)", RelocationData);
					#endif

					for (DWORD i = 0; i < NumRelocs; ++i, ++RelocationData)
					{
						if (ProcessRelocation(ImageBaseDelta, *RelocationData, RelocBase) == FALSE)
						{
							#ifdef DEBUG_MESSAGES_ENABLED
							DebugShout("[ProcessRelocations] Unable to process relocation (%i)", i);
							#endif
						}
					}

					RelocationDirectory = reinterpret_cast<PIMAGE_BASE_RELOCATION>(RelocationData);
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
			DebugShout("[ProcessRelocations] Relocations have have not been found in this executable, continuing..");
			#endif
			return TRUE;
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
	DebugShout("[ProcessSection] ProcessSection( %s, 0x%IX, 0x%IX, 0x%IX, 0x%IX, 0x%IX, 0x%IX, 0x%IX )", Name, BaseAddress, RemoteAddress, RawData, VirtualAddress, RawSize, VirtualSize, ProtectFlag);
	#endif

	if (WriteProcessMemory(m_hProcess, MakePtr(PVOID, RemoteAddress, VirtualAddress), MakePtr(PVOID, BaseAddress, RawData), (SIZE_T)RawSize, NULL) == FALSE)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessSection] Failed to write memory for [%s] -> [%s]", Name, LastErrorString());
		#endif
		return FALSE;
	}

	DWORD dwOldProtect = NULL;
	if (VirtualProtectEx(m_hProcess, MakePtr(PVOID, RemoteAddress, VirtualAddress), (SIZE_T)VirtualSize, ProtectFlag, &dwOldProtect) == FALSE)
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
			#endif
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessSections] Mapped PE Header successfully!");
			#endif
		}
	}
	else
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[ProcessSections] PE Header mapping disabled, skipping.");
		#endif
	}

	// Write individual sections
	PIMAGE_SECTION_HEADER ImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);
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
				#endif
			}
			else
			{
				#ifdef DEBUG_MESSAGES_ENABLED
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
	DebugShout("[ProcessTlsEntries] TlsDirectory (0x%IX)", TlsDirectory);
	#endif

	if (TlsDirectory->AddressOfCallBacks == NULL)
		return TRUE; // Success when there is no Tls entries / broken data?

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[ProcessTlsEntries] TlsDirectory->AddressOfCallBacks (0x%IX)", TlsDirectory->AddressOfCallBacks);
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
		DebugShout("[ProcessTlsEntries] TLSCallbacks[%i] = 0x%IX (0x%IX)", i, TLSCallbacks[i], RemoteAddress);
		#endif

		// As a consequence of the relocation stuff mentioned above, pCallbacks[i] is already fixed
		if (CallEntryPoint(RemoteAddress, (FARPROC)TLSCallbacks[i]) == false)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessTlsEntries] Failed to execute Tls Entry [%i]", i);
			#endif
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[ProcessTlsEntries] Called Tls Callback (0x%IX)", TLSCallbacks[i]);
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
	DebugShout("[InitModuleFile] Size [0x%IX]", r.Size);
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
		DebugShout("[InitModuleFile] Read file complete [0x%IX]", NumberOfBytesRead);
		#endif

		r.Buffer = AllocatedFile;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("[InitModuleFile] Buffer [0x%IX]", r.Buffer);
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
	return Utils::GetProcessPlatform(m_hProcess);
}


//
// Deprecated functions that don't work with everything
//
FARPROC CRemoteLoader::GetRemoteProcAddress_DEPRECATED(HMODULE Module, LPCCH Function)
{
	if (!Module)
	{
#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl_DEPRECATED(Module, (const char*)Function);
}

FARPROC CRemoteLoader::GetRemoteProcAddress_DEPRECATED(LPCCH Module, LPCCH Function)
{
	HMODULE hMod = GetRemoteModuleHandleA(Module);
	if (!hMod)
		hMod = LoadDependencyA(Module);
	if (!hMod)
	{
#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl_DEPRECATED(hMod, (const char*)Function);
}

FARPROC CRemoteLoader::GetRemoteProcAddress_DEPRECATED(HMODULE Module, SHORT Function)
{
	if (!Module)
	{
#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl_DEPRECATED(Module, (const char*)Function);
}

FARPROC CRemoteLoader::GetRemoteProcAddress_DEPRECATED(LPCCH Module, SHORT Function)
{
	HMODULE hMod = GetRemoteModuleHandleA(Module);
	if (!hMod)
		hMod = LoadDependencyA(Module);
	if (!hMod)
	{
#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("CRemoteLoader[GetRemoteProcAddress] LoadLibrary failed to load module!");
#endif
		return NULL;
	}
	return (FARPROC)GetRemoteProcAddressImpl_DEPRECATED(hMod, (const char*)Function);
}

void* CRemoteLoader::GetRemoteProcAddressImpl_DEPRECATED(HMODULE module, const char *proc_name)
{
	char* modb = (char*)module;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER *)modb;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS *)(modb + dos_header->e_lfanew);

	IMAGE_OPTIONAL_HEADER *opt_header = &nt_headers->OptionalHeader;
	IMAGE_DATA_DIRECTORY *exp_entry = (IMAGE_DATA_DIRECTORY *)(&opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY *exp_dir = (IMAGE_EXPORT_DIRECTORY *)((size_t)modb + exp_entry->VirtualAddress);

	DWORD* func_table = (DWORD*)((size_t)modb + exp_dir->AddressOfFunctions);
	WORD*  ord_table = (WORD *)((size_t)modb + exp_dir->AddressOfNameOrdinals);
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
		{
			frwd_module = (HMODULE)LoadDependencyA(dllName);
			if (!frwd_module)
			{
				printf("GetRemoteProcAddress failed to load module using GetRemoteModuleHandle and LoadLibrary!");
				return NULL;
			}
		}

		bool forwardByOrd = strchr(func_name, '#') == 0 ? false : true;
		if (forwardByOrd) // forwarded by ordinal
		{
			WORD func_ord = atoi(func_name + 1);
			address = GetRemoteProcAddressImpl_DEPRECATED(frwd_module, (const char*)func_ord);
		}
		else
		{
			address = GetRemoteProcAddressImpl_DEPRECATED(frwd_module, func_name);
		}

		free(dll_name);
	}
	return address;
}
