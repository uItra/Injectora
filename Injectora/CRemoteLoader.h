#include "CRemoteCode.h"

#ifdef UNICODE
#undef UNICODE
#endif

#ifndef _CREMOTELOAD_H_
#define _CREMOTELOAD_H_

#ifndef IMR_RELTYPE
#define IMR_RELTYPE(x)				((x >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#define IMR_RELOFFSET(x)			(x & 0xFFF)
#endif

#define MakePtr(cast, ptr, addValue) (cast)((DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define MakeDelta(cast, x, y) (cast)((DWORD_PTR)(x) - (DWORD_PTR)(y))

struct ModuleFile
{
	PVOID							Buffer;
	int								Size;

	bool IsValid() { return ( Buffer && Size ); }
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

class CRemoteLoader : public CRemoteCode
{
public:
	void							SetProcess(HANDLE hProcess);

	HMODULE							LoadDependencyA(LPCCH Path);
	HMODULE							LoadDependencyW(LPCWCH Path);
	HMODULE							LoadLibraryByPathA(LPCCH Path, ULONG Flags = NULL);
	HMODULE							LoadLibraryByPathW(LPCWCH Path, ULONG Flags = NULL);
	HMODULE							LoadLibraryByPathIntoMemoryA(LPCCH Path, BOOL PEHeader);
	HMODULE							LoadLibraryByPathIntoMemoryW(LPCWCH Path, BOOL PEHeader);
	HMODULE							LoadLibraryFromMemory(PVOID BaseAddress, DWORD SizeOfModule, BOOL PEHeader);

private:
	HMODULE							GetRemoteModuleHandleA(LPCCH Module);
	HMODULE							GetRemoteModuleHandleW(LPCWCH Module);

	void*							GetRemoteProcAddressImpl_DEPRECATED(HMODULE module, const char *proc_name);

public:
	FARPROC							GetRemoteProcAddressA(LPCCH module, SHORT procOrdinal);
	FARPROC							GetRemoteProcAddressW(LPCWCH module, SHORT procOrdinal);

	FARPROC							GetRemoteProcAddressA(LPCCH module, LPCCH procName);
	FARPROC							GetRemoteProcAddressW(LPCWCH module, LPCWCH procName);

	FARPROC							GetRemoteProcAddress_DEPRECATED(HMODULE Module, LPCCH Function);
	FARPROC							GetRemoteProcAddress_DEPRECATED(HMODULE Module, SHORT Function);
	FARPROC							GetRemoteProcAddress_DEPRECATED(LPCCH Module, LPCCH Function);
	FARPROC							GetRemoteProcAddress_DEPRECATED(LPCCH Module, SHORT Function);

protected:
	IMAGE_DOS_HEADER*				ToDos(PVOID BaseAddress);
	IMAGE_NT_HEADERS*				ToNts(PVOID BaseAddress);

	PVOID							RvaToPointer(ULONG RVA, PVOID BaseAddress);

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