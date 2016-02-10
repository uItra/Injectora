#include "JuceHeader.h"
#include "Utils.h"

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

#ifdef _WIN64
#define _PARAMETER_TYPE_DWORD PARAMETER_TYPE_INT | PARAMETER_TYPE_FLOAT | PARAMETER_TYPE_SHORT
#define _PARAMETER_TYPE_QWORD PARAMETER_TYPE_INT64 | PARAMETER_TYPE_DOUBLE | PARAMETER_TYPE_POINTER | PARAMETER_TYPE_STRING | PARAMETER_TYPE_WSTRING
#else
#define _PARAMETER_TYPE_DWORD PARAMETER_TYPE_INT | PARAMETER_TYPE_FLOAT | PARAMETER_TYPE_SHORT | PARAMETER_TYPE_POINTER | PARAMETER_TYPE_STRING | PARAMETER_TYPE_WSTRING
#define _PARAMETER_TYPE_QWORD PARAMETER_TYPE_INT64 | PARAMETER_TYPE_DOUBLE
#endif
#define _PARAMETER_TYPE_STRING PARAMETER_TYPE_STRING | PARAMETER_TYPE_WSTRING

//
typedef enum {
	PARAMETER_INDEX_RCX,
	PARAMETER_INDEX_RDX,
	PARAMETER_INDEX_R8,
	PARAMETER_INDEX_R9,
	PARAMETER_INDEX_MAX
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

	#ifdef DEBUG_MESSAGES_ENABLED
	void					DebugShout(const char *szShout, ...);
	void					DebugShoutBufferHex();
	#endif

protected:
	HANDLE					CreateRemoteThreadInProcess(LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam);

	void					Prologue64();

	void					AddByteToBuffer(unsigned char in);
	void					AddLongToBuffer(unsigned long in);
	void					AddLong64ToBuffer(unsigned __int64 in);
	void					LoadStringParam64(parameter_info_t paraminfo, parameter_index_t paramindex);
	bool					LoadParam64(unsigned __int64 param, parameter_index_t paramindex);
	size_t					PushAllParameters(bool right_to_left = true);


	void					Epilogue64();

protected:
	HANDLE					m_hProcess;
	bool					m_bIs64bit;

	tNTQIP					fnNTQIP;
	tNTQSI					fnNTQSI;

	invoke_info_t			m_CurrentInvokeInfo;
	remote_thread_buffer_t	m_CurrentRemoteThreadBuffer;

	char					m_baseDir[MAX_PATH];
	char					m_infoLog[MAX_PATH];
	ofstream				m_logFile;

};

#endif