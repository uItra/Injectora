#include "JuceHeader.h"
#include "Utils.h"

#ifndef _CREMOTECODE_H_
#define _CREMOTECODE_H_

using namespace std;

//these are the only types supported at the moment
typedef enum {
	CCONV_CDECL = 0,
	CCONV_STDCALL,
	CCONV_THISCALL,
	CCONV_FASTCALL
} calling_convention_t;

//
typedef enum {
	PARAMETER_TYPE_INT = 0,
	PARAMETER_TYPE_INT64,
	PARAMETER_TYPE_BOOL,
	PARAMETER_TYPE_SHORT,
	PARAMETER_TYPE_FLOAT,
	PARAMETER_TYPE_DOUBLE,
	PARAMETER_TYPE_BYTE,
	PARAMETER_TYPE_POINTER,
	PARAMETER_TYPE_STRING,
	PARAMETER_TYPE_WSTRING
} parameter_type_t;

//
typedef struct {
	parameter_type_t			ptype;
	void*						pparam;
} parameter_info_t;

//
typedef struct {
	ULONG						size;
	void*						ptr;
} string_alloc_t;

//
typedef struct {
	calling_convention_t		cconv;
	vector<parameter_info_t>	params;
	vector<string_alloc_t>		strings;
	#ifdef _WIN64
	unsigned __int64			calladdress;
	#else
	unsigned long				calladdress;
	#endif
} invoke_info_t;

//
typedef vector<unsigned char>	remote_thread_buffer_t;

class CRemoteCode
{
public:
	void					SetProcess(HANDLE hProcess);

	void					PushParameter(parameter_type_t param_type, void *param);

	void					PushInt(int i);
	void					PushInt64(__int64 i);
	void					PushBool(bool b);
	void					PushShort(short s);
	void					PushFloat(float f);
	void					PushDouble(double d);
	void					PushByte(unsigned char uc);
	void					PushPointer(void *ptr);
	void					PushPointer64(void *ptr);
	void					PushANSIString(const char* szString);
	void					PushUNICODEString(const wchar_t* szString);

	void					PushCall(calling_convention_t cconv, FARPROC CallAddress);

	remote_thread_buffer_t	AssembleRemoteThreadBuffer();
	remote_thread_buffer_t	GetRemoteThreadBuffer();

	bool					ExecuteRemoteThreadBuffer(remote_thread_buffer_t thread_data, bool async = true);
	void					DestroyRemoteThreadBuffer();

	void*					CommitMemory(void *data, SIZE_T size_of_data);
	void*					RemoteAllocateMemory(SIZE_T size);
	void					RemoteFreeMemory(void *address, SIZE_T size);

	string					CallingConventionToString(calling_convention_t cconv);
	string					ParameterTypeToString(parameter_type_t type);

	HANDLE					GetProcess() { return m_hProcess; }

	#ifdef DEBUG_MESSAGES_ENABLED
	void					DebugShout(const char *szShout, ...);
	void					DebugShoutBufferHex();
	#endif

protected:
	HANDLE					CreateRemoteThreadInProcess(LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam);
	void					AddByteToBuffer(unsigned char in);
	void					AddLongToBuffer(unsigned long in);
	void					AddLong64ToBuffer(unsigned __int64 in);
	void					PushAllParameters(bool right_to_left = true);

protected:
	HANDLE					m_hProcess;
	bool					m_bIs64bit;

	invoke_info_t			m_CurrentInvokeInfo;
	remote_thread_buffer_t	m_CurrentRemoteThreadBuffer;

	char					m_baseDir[MAX_PATH];
	char					m_infoLog[MAX_PATH];
	ofstream				m_logFile;

private:
	static LONG GetProcessorArchitecture()
	{
		static LONG volatile nProcessorArchitecture = -1;
		if (nProcessorArchitecture == -1)
		{
			SYSTEM_PROCESSOR_INFORMATION sProcInfo;
			NTSTATUS nNtStatus;
	
			tRtlGetNativeSystemInformation fnRtlGetNativeSystemInformation = (tRtlGetNativeSystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlGetNativeSystemInformation");
	
			nNtStatus = fnRtlGetNativeSystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo, sizeof(sProcInfo), NULL);
			if (nNtStatus == STATUS_NOT_IMPLEMENTED)
			{
				tNTQSI fnNtQuerySystemInformation = (tNTQSI)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
				nNtStatus = fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessorInformation, &sProcInfo, sizeof(sProcInfo), NULL);
			}
			if (NT_SUCCESS(nNtStatus))
				_InterlockedExchange(&nProcessorArchitecture, (LONG)(sProcInfo.ProcessorArchitecture));
		}
		return nProcessorArchitecture;
	}

	static NTSTATUS GetProcessPlatform(HANDLE hProcess)
	{
		if (hProcess == (HANDLE)((LONG_PTR)-1))
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
	
			tNTQIP fnNtQueryInformationProcess = (tNTQIP)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
	
			nNtStatus = fnNtQueryInformationProcess(hProcess, ProcessWow64Information, &nWow64, sizeof(nWow64), NULL);
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
};

#endif