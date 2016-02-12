#include "CRemoteCode.h"

#include "ApiSet.h"

#include <map>

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
	CRemoteLoader()					{ InitializeApiSchema(); }

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

	PVOID							RvaToPointer( ULONG RVA, PVOID BaseAddress );

	BOOL							CallEntryPoint( PVOID BaseAddress, FARPROC Entrypoint );

	BOOL							ProcessDelayedImportTable(PVOID BaseAddress, PVOID RemoteAddress );
	BOOL							ProcessImportTable( PVOID BaseAddress, PVOID RemoteAddress );
	BOOL							ProcessRelocation( size_t ImageBaseDelta, WORD Data, PBYTE RelocationBase );
	BOOL							ProcessRelocations( PVOID BaseAddress, PVOID RemoteAddress );
	BOOL							ProcessTlsEntries( PVOID BaseAddress, PVOID RemoteAddress );
	ULONG							GetSectionProtection( ULONG Characteristics );
	BOOL							ProcessSection( BYTE* Name, PVOID BaseAddress, PVOID RemoteAddress, ULONGLONG RawData, ULONGLONG VirtualAddress, ULONGLONG RawSize, ULONGLONG VirtualSize, ULONG ProtectFlag );
	BOOL							ProcessSections( PVOID BaseAddress, PVOID RemoteAddress, BOOL MapPEHeader );

private:
	ModuleFile						InitModuleFile(LPCCH FileName);
	BOOL							FreeModuleFile(ModuleFile Handle);
	TCHAR*							LastErrorString();

	LONG							GetProcessorArchitecture();
	int								GetProcessPlatform();

private:
	typedef std::map<std::wstring, std::vector<std::wstring>> MapApiSchema;
	MapApiSchema m_ApiSchemaMap;

	HANDLE m_hActx;

	// Initialize api set map
	bool InitializeApiSchema()
	{
		if (SystemStats::IsWindowsVersionOrLater(SystemStats::Windows10))
			return InitializeP< PAPI_SET_NAMESPACE_ARRAY_10,
			PAPI_SET_NAMESPACE_ENTRY_10,
			PAPI_SET_VALUE_ARRAY_10,
			PAPI_SET_VALUE_ENTRY_10 >();
		else if (SystemStats::IsWindowsVersionOrLater(SystemStats::Windows8))
			return InitializeP< PAPI_SET_NAMESPACE_ARRAY,
			PAPI_SET_NAMESPACE_ENTRY,
			PAPI_SET_VALUE_ARRAY,
			PAPI_SET_VALUE_ENTRY >();
		else if (SystemStats::IsWindowsVersionOrLater(SystemStats::Windows7))
			return InitializeP< PAPI_SET_NAMESPACE_ARRAY_V2,
			PAPI_SET_NAMESPACE_ENTRY_V2,
			PAPI_SET_VALUE_ARRAY_V2,
			PAPI_SET_VALUE_ENTRY_V2 >();
		else
			return true;
	}

	// OS dependent api set initialization
	template<typename T1, typename T2, typename T3, typename T4>
	bool InitializeP()
	{
		if (!m_ApiSchemaMap.empty())
			return true;

		PEB_T *ppeb = reinterpret_cast<PEB_T*>(reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock);
		T1 pSetMap = reinterpret_cast<T1>(ppeb->ApiSetMap);

		for (DWORD i = 0; i < pSetMap->Count; i++)
		{
			T2 pDescriptor = pSetMap->entry(i);

			std::vector<std::wstring> vhosts;
			wchar_t dllName[MAX_PATH] = { 0 };

			pSetMap->apiName(pDescriptor, dllName);
			std::transform(dllName, dllName + MAX_PATH, dllName, ::tolower);

			T3 pHostData = pSetMap->valArray(pDescriptor);

			for (DWORD j = 0; j < pHostData->Count; j++)
			{
				T4 pHost = pHostData->entry(pSetMap, j);
				std::wstring hostName(reinterpret_cast<wchar_t*>(reinterpret_cast<uint8_t*>(pSetMap)+pHost->ValueOffset), pHost->ValueLength / sizeof(wchar_t));

				if (!hostName.empty())
					vhosts.push_back(hostName);
			}

			m_ApiSchemaMap.insert(std::make_pair(dllName, vhosts));
		}

		return true;
	}


	// Resolve path flags
	enum eResolveFlag
	{
		Default = 0,
		ApiSchemaOnly = 1,
		EnsureFullPath = 2,
	};

	/*
	Resolve dll path

	IN:
	path - dll path
	baseName - name of base import dll (API Schema resolve only)

	OUT:
	path - resolved path

	RETURN:
	Error code
	*/
	DWORD ResolvePath(std::wstring& path, eResolveFlag flags, const std::wstring& baseName = L"")
	{
		wchar_t tmpPath[4096] = { 0 };
		std::wstring completePath;

		std::transform(path.begin(), path.end(), path.begin(), ::tolower);

		std::wstring filename = Utils::StripPath(path);

		// 'ext-ms-' are resolved the same way 'api-ms-' are
		if (filename.find( L"ext-ms-" ) == 0)
			filename.erase( 0, 4 );

		//
		// ApiSchema redirection
		//
		auto iter = m_ApiSchemaMap.find(filename);
		if (iter != m_ApiSchemaMap.end())
		{
			// Select appropriate api host
			path = iter->second.front() != baseName ? iter->second.front() : iter->second.back();

			if (ProbeSxSRedirect(path) == STATUS_SUCCESS)
				return STATUS_SUCCESS;
			else if (flags & EnsureFullPath)
			{
				wchar_t sys_path[255] = { 0 };
				GetSystemDirectoryW(sys_path, 255);
				path = sys_path + path;
			}

			return STATUS_SUCCESS;
		}

		if (flags & ApiSchemaOnly)
		{
			SetLastError(ERROR_NOT_FOUND);
			return ERROR_NOT_FOUND;
		}

		// SxS redirection
		if (ProbeSxSRedirect(path) == ERROR_SUCCESS)
			return ERROR_SUCCESS;

		//
		// Perform search accordingly to Windows Image loader search order 
		// 1. KnownDlls
		//
		HKEY hKey = NULL;
		LRESULT res = 0;
		res = RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", &hKey);

		if (res == 0)
		{
			for (int i = 0; i < 0x1000 && res == ERROR_SUCCESS; i++)
			{
				wchar_t value_name[255] = { 0 };
				wchar_t value_data[255] = { 0 };

				DWORD dwSize = 255;
				DWORD dwType = 0;

				res = RegEnumValueW(hKey, i, value_name, &dwSize, NULL, &dwType, reinterpret_cast<LPBYTE>(value_data), &dwSize);

				if (_wcsicmp(value_data, filename.c_str()) == 0)
				{
					wchar_t sys_path[255] = { 0 };
					dwSize = 255;
	
					// In Win10 DllDirectory value got screwed, so less reliable method is used
					GetSystemDirectoryW(sys_path, dwSize);

					if (res == ERROR_SUCCESS)
					{
						path = std::wstring(sys_path) + L"\\" + value_data;

						RegCloseKey(hKey);
						return ERROR_SUCCESS;
					}
				}
			}

			RegCloseKey(hKey);
		}

		//
		// 2. The directory from which the application loaded.
		//
		completePath = Utils::GetProcessDirectory(m_hProcess) + L"\\" + filename;
		if (Utils::FileExists(completePath))
		{
			path = completePath;
			return ERROR_SUCCESS;
		}

		//
		// 3. The system directory
		//
		GetSystemDirectoryW(tmpPath, ARRAYSIZE(tmpPath));
		completePath = std::wstring(tmpPath) + L"\\" + filename;
		if (Utils::FileExists(completePath))
		{
			path = completePath;
			return ERROR_SUCCESS;
		}


		//
		// 4. The Windows directory
		//
		GetWindowsDirectoryW(tmpPath, ARRAYSIZE(tmpPath));
		completePath = std::wstring(tmpPath) + L"\\" + filename;
		if (Utils::FileExists(completePath))
		{
			path = completePath;
			return ERROR_SUCCESS;
		}

		//
		// 5. The current directory
		//
		GetCurrentDirectoryW(ARRAYSIZE(tmpPath), tmpPath);
		completePath = std::wstring(tmpPath) + L"\\" + filename;
		if (Utils::FileExists(completePath))
		{
			path = completePath;
			return ERROR_SUCCESS;
		}

		//
		// 6. The directories listed in the PATH environment variable
		//
		GetEnvironmentVariableW(L"PATH", tmpPath, ARRAYSIZE(tmpPath));
		wchar_t *pContext;

		for (wchar_t *pDir = wcstok_s(tmpPath, L";", &pContext); pDir; pDir = wcstok_s(pContext, L";", &pContext))
		{
			completePath = std::wstring(pDir) + L"\\" + filename;
			if (Utils::FileExists(completePath))
			{
				path = completePath;
				return ERROR_SUCCESS;
			}
		}

		SetLastError(ERROR_NOT_FOUND);
		return ERROR_NOT_FOUND;
	}

	/*
	Try SxS redirection
	*/
	DWORD ProbeSxSRedirect(std::wstring& path)
	{
		UNICODE_STRING OriginalName;
		UNICODE_STRING DllName1;
		UNICODE_STRING DllName2;
		PUNICODE_STRING pPath = nullptr;
		ULONG_PTR cookie = 0;
		wchar_t wBuf[255] = { 0 };

		//if (path.rfind(L".dll") != std::wstring::npos)
			//path.erase(path.rfind(L".dll"));

		static HMODULE hNtdll = Utils::GetLocalModuleHandle("ntdll.dll");
		static tRtlInitUnicodeString RtlInitUnicodeString = (tRtlInitUnicodeString)Utils::GetProcAddress(hNtdll, "RtlInitUnicodeString");
		static tRtlFreeUnicodeString RtlFreeUnicodeString = (tRtlFreeUnicodeString)Utils::GetProcAddress(hNtdll, "RtlFreeUnicodeString");
		static tRtlNtStatusToDosError RtlNtStatusToDosError = (tRtlNtStatusToDosError)Utils::GetProcAddress(hNtdll, "RtlNtStatusToDosError");
		static tRtlDosApplyFileIsolationRedirection_Ustr RtlDosApplyFileIsolationRedirection_Ustr = (tRtlDosApplyFileIsolationRedirection_Ustr)Utils::GetProcAddress(hNtdll, "RtlDosApplyFileIsolationRedirection_Ustr");

		RtlInitUnicodeString(&OriginalName, path.c_str());

		DllName1.Buffer = wBuf;
		DllName1.Length = NULL;
		DllName1.MaximumLength = ARRAYSIZE(wBuf);

		// Use activation context
		if (m_hActx && m_hActx != INVALID_HANDLE_VALUE)
			ActivateActCtx(m_hActx, &cookie);

		// SxS resolve
		NTSTATUS status = RtlDosApplyFileIsolationRedirection_Ustr(TRUE, &OriginalName, NULL, &DllName1, &DllName2, &pPath, NULL, NULL, NULL);

		if (cookie != 0 && m_hActx && m_hActx != INVALID_HANDLE_VALUE)
			DeactivateActCtx(0, cookie);

		if (status == STATUS_SUCCESS)
		{
			path = pPath->Buffer;
		}
		else
		{
			if (DllName2.Buffer)
				RtlFreeUnicodeString(&DllName2);

			//path.append(L".dll");
			SetLastError(RtlNtStatusToDosError(status));
			return RtlNtStatusToDosError(status);
		}

		if (DllName2.Buffer)
			RtlFreeUnicodeString(&DllName2);

		SetLastError(ERROR_SUCCESS);
		return ERROR_SUCCESS;
	}

};



#endif