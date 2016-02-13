#include "JuceHeader.h"
#include "Utils.h"
#include "ProcessInfo.h"

#include <shlobj.h>

#ifndef _CREMOTECODE_H_
#define _CREMOTECODE_H_

using namespace std;

// these are the only types supported at the moment
typedef enum {
	CCONV_CDECL = 0,
	CCONV_STDCALL,
	CCONV_THISCALL,
	CCONV_FASTCALL,
	CCONV_WIN64
} calling_convention_t;

//
typedef enum {
	PARAM_TYPE_INT = 0,
	PARAM_TYPE_INT64,
	PARAM_TYPE_BOOL,
	PARAM_TYPE_SHORT,
	PARAM_TYPE_FLOAT,
	PARAM_TYPE_DOUBLE,
	PARAM_TYPE_BYTE,
	PARAM_TYPE_POINTER,
	PARAM_TYPE_STRING,
	PARAM_TYPE_WSTRING,
	PARAM_TYPE_UNICODE_STRUCT
} parameter_type_t;

#ifdef _WIN64
#define _PARAM_TYPE_DWORD(paramType) paramType == PARAM_TYPE_INT || paramType == PARAM_TYPE_FLOAT || paramType == PARAM_TYPE_SHORT
#define _PARAM_TYPE_QWORD(paramType) paramType == PARAM_TYPE_INT64 || paramType == PARAM_TYPE_DOUBLE || paramType == PARAM_TYPE_POINTER || paramType == PARAM_TYPE_STRING || paramType == PARAM_TYPE_WSTRING
#define _PARAM_TYPE_STRING(paramType) paramType == PARAM_TYPE_STRING || paramType == PARAM_TYPE_WSTRING || paramType == PARAM_TYPE_UNICODE_STRUCT
#else
#define _PARAM_TYPE_DWORD PARAM_TYPE_INT || PARAM_TYPE_FLOAT || PARAM_TYPE_SHORT || PARAM_TYPE_POINTER || PARAM_TYPE_STRING || PARAM_TYPE_WSTRING
#define _PARAM_TYPE_QWORD PARAM_TYPE_INT64 || PARAM_TYPE_DOUBLE
#define _PARAM_TYPE_STRING(paramType) paramType == PARAM_TYPE_STRING || paramType == PARAM_TYPE_WSTRING || paramType == PARAM_TYPE_UNICODE_STRUCT
#endif

//
typedef enum {
	PARAM_INDEX_RCX,
	PARAM_INDEX_RDX,
	PARAM_INDEX_R8,
	PARAM_INDEX_R9,
	PARAM_INDEX_MAX
} parameter_index_t;

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
	ULONG						size;
	void*						ptr;
} struct_alloc_t;

//
typedef struct {
	calling_convention_t		cconv;
	vector<parameter_info_t>	params;
	vector<string_alloc_t>		strings;
	vector<struct_alloc_t>		structs;
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
	void					PushParameter(parameter_type_t param_type, void *param);

	void					PushInt(int i);
	void					PushUInt(unsigned int i);
	void					PushInt64(__int64 i);
	void					PushUInt64(unsigned __int64 i);
	void					PushBool(bool b);
	void					PushShort(short s);
	void					PushFloat(float f);
	void					PushDouble(double d);
	void					PushByte(unsigned char uc);
	void					PushPointer(void *ptr);
	void					PushPointer64(void *ptr);
	void					PushANSIString(const char* szString);
	void					PushUNICODEString(const wchar_t* szString);
	void					PushUNICODEStringStructure(UNICODE_STRING* ptrUnicodeString);

	void					PushCall(calling_convention_t cconv, FARPROC CallAddress);

	remote_thread_buffer_t	GetRemoteThreadBuffer();

	DWORD					ExecuteInWorkerThread(remote_thread_buffer_t buffer, size_t& callResult);
	DWORD					TerminateWorkerThread();

	bool					ExecuteRemoteThreadBuffer(remote_thread_buffer_t thread_data, bool async = true);
	void					DestroyRemoteThreadBuffer();

	void*					CommitMemory(void *data, SIZE_T size_of_data);
	void*					RemoteAllocateMemory(SIZE_T size);
	void					RemoteFreeMemory(void *address, SIZE_T size);

	string					CallingConventionToString(calling_convention_t cconv);
	string					ParameterTypeToString(parameter_type_t type);

	bool					SetBaseDirectory();

	#ifdef DEBUG_MESSAGES_ENABLED
	void					DebugShout(const char *szShout, ...);
	void					DebugShoutBufferHex();
	#endif

protected:
	HANDLE					CreateRemoteThreadInProcess(LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam);

	void					BeginCall64();

	void					AddByteToBuffer(unsigned char in);
	void					AddLongToBuffer(unsigned long in);
	void					AddLong64ToBuffer(unsigned __int64 in);
	void					LoadStringParam64(parameter_info_t paraminfo, parameter_index_t paramindex);
	bool					LoadParam64(unsigned __int64 param, parameter_index_t paramindex);
	void					PushAllParameters(bool right_to_left = true);

	void					EndCall64();

protected:
	DWORD					CreateRPCEnvironment(bool noThread = false);
	bool					CreateAPCEvent(DWORD threadID);
	DWORD					CreateWorkerThread();

	void					ExitThreadWithStatus();
	void					SaveRetValAndSignalEvent();

	bool					CreateActxFromManifest(const char* Manifest);

protected:
	HANDLE					m_hProcess;
	bool					m_bIs64bit;

	tNTQIP					fnNTQIP;
	tNTQSI					fnNTQSI;

	invoke_info_t			m_CurrentInvokeInfo;
	remote_thread_buffer_t	m_CurrentRemoteThreadBuffer;

	HANDLE					m_hWaitEvent; // APC sync event handle
	HANDLE					m_hWorkThd;  // Worker thread handle
	void*					m_pWorkerCode;
	void*					m_pWorkerCodeThread; // m_pWorkCode + space
	void*					m_pUserCode; // m_pWorkCode + space + m_pWorkCodeSize
	size_t					m_dwWorkerCodeSize;

	void*					m_pAContext;        // SxS activation context memory address

	bool					m_bBaseDirIsSet;
	char					m_baseDir[MAX_PATH];
	char					m_infoLog[MAX_PATH];
	
	char					m_tempManifest[MAX_PATH];

	ofstream				m_logFile;

};

#endif