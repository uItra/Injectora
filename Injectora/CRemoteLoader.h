#include "CRemoteCode.h"

#ifndef _CREMOTELOAD_H_
#define _CREMOTELOAD_H_

#ifndef IMR_RELTYPE
#define IMR_RELTYPE(x)				((x >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#define IMR_RELOFFSET(x)			(x & 0xFFF)
#endif

struct ModuleFile
{
	PVOID							Buffer;
	INT								Size;

	BOOL IsValid() { return ( Buffer && Size ); }
};

// Relocation block information
struct RelocData
{
	ULONG VirtualAddress;
	ULONG SizeOfBlock;

	struct
	{
		WORD Offset : 12;
		WORD Type : 4;
	}Item[1];
};

class ExportData
{
public:
	ExportData()
	{
		procAddress = 0;
		forwardOrdinal = 0;
		isForwarded = false;
		forwardByOrd = false;
	}

	DWORD_PTR procAddress;          // Function address

	LPCCH forwardModule;     // Name of forward module
	LPCCH forwardName;        // Forwarded function name
	WORD forwardOrdinal;        // Forwarded function ordinal

	bool isForwarded;       // Function is forwarded to another module
	bool forwardByOrd;      // Forward is done by ordinal
};

class CRemoteLoader : public CRemoteCode
{
public:
	void							SetProcess(HANDLE hProcess);

	HMODULE							LoadLibraryByPathA(LPCCH Path);
	HMODULE							LoadLibraryByPathW(LPCWCH Path);
	HMODULE							LoadLibraryByPathIntoMemoryA(LPCCH Path, BOOL PEHeader);
	HMODULE							LoadLibraryByPathIntoMemoryW(LPCWCH Path, BOOL PEHeader);
	HMODULE							LoadLibraryFromMemory(PVOID BaseAddress, DWORD SizeOfModule, BOOL PEHeader);

private:
	HMODULE							GetRemoteModuleHandleA(LPCCH Module);
	HMODULE							GetRemoteModuleHandleW(LPCWCH Module);

	void*							GetRemoteProcAddressImpl(HMODULE module, const char *proc_name);

public:
	FARPROC							GetRemoteProcAddress(HMODULE Module, LPCCH Function);
	FARPROC							GetRemoteProcAddress(HMODULE Module, SHORT Function);
	FARPROC							GetRemoteProcAddress(LPCCH Module, LPCCH Function);
	FARPROC							GetRemoteProcAddress(LPCCH Module, SHORT Function);

protected:
	IMAGE_DOS_HEADER*				ToDos(PVOID BaseAddress);
	IMAGE_NT_HEADERS*				ToNts(PVOID BaseAddress);

	PVOID							RvaToPointer(ULONG RVA, PVOID BaseAddress);

	PVOID							ImageDirectoryEntryToData( PVOID BaseAddress, USHORT DataDirectory );
	BOOL							CallEntryPoint( PVOID BaseAddress, FARPROC Entrypoint );

	BOOL							ProcessDelayedImportTable(PVOID BaseAddress, PVOID RemoteAddress);
	BOOL							ProcessImportTable( PVOID BaseAddress, PVOID RemoteAddress);
	BOOL							ProcessRelocation( ULONG ImageBaseDelta, WORD Data, PBYTE RelocationBase);
	BOOL							ProcessRelocations( PVOID BaseAddress, PVOID RemoteAddress );
	BOOL							ProcessTlsEntries( PVOID BaseAddress, PVOID RemoteAddress );
	ULONG							GetSectionProtection( ULONG Characteristics );
	BOOL							ProcessSection( BYTE* Name, PVOID BaseAddress, PVOID RemoteAddress, ULONGLONG RawData, ULONGLONG VirtualAddress, ULONGLONG RawSize, ULONGLONG VirtualSize, ULONG ProtectFlag);
	BOOL							ProcessSections( PVOID BaseAddress, PVOID RemoteAddress, BOOL MapPEHeader );

private:
	DWORD							CreateRPCEnvironment(bool noThread = false);

	ModuleFile						InitModuleFile(LPCCH FileName);
	BOOL							FreeModuleFile(ModuleFile Handle);
	TCHAR*							LastErrorString();

	LONG							GetProcessorArchitecture();
	int								GetProcessPlatform();

};



#endif