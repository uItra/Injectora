#include <windows.h>
#include <iostream>

#include "CRemoteCode.h"
#ifdef DEBUG_MESSAGES_ENABLED
#include <shlobj.h>
#endif
#include <time.h>

void CRemoteCode::PushParameter(parameter_type_t param_type, void *param)
{
	parameter_info_t pi;

	pi.ptype = param_type;
	pi.pparam = param;

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("Adding parameter to function [%i][0x%IX]", pi.ptype, pi.pparam);
	#endif

	m_CurrentInvokeInfo.params.push_back(pi);
}

void CRemoteCode::PushUInt(unsigned int i)
{
	unsigned int *iUse = new unsigned int;
	*iUse = i;
	PushParameter(PARAM_TYPE_INT, iUse);
}

void CRemoteCode::PushInt(int i)
{
	int *iUse = new int;
	*iUse = i;
	PushParameter(PARAM_TYPE_INT, iUse);
}

void CRemoteCode::PushUInt64(unsigned __int64 i)
{
	unsigned __int64 *iUse = new unsigned __int64;
	*iUse = i;
	PushParameter(PARAM_TYPE_INT64, iUse);
}

void CRemoteCode::PushInt64(__int64 i)
{
	__int64 *iUse = new __int64;
	*iUse = i;
	PushParameter(PARAM_TYPE_INT64, iUse);
}

void CRemoteCode::PushBool(bool b)
{
	bool *bUse = new bool;
	*bUse = b;
	PushParameter(PARAM_TYPE_BOOL, bUse);
}

void CRemoteCode::PushShort(short s)
{
	short *sUse = new short;
	*sUse = s;
	PushParameter(PARAM_TYPE_SHORT, sUse);
}

void CRemoteCode::PushFloat(float f)
{
	float *fUse = new float;
	*fUse = f;
	PushParameter(PARAM_TYPE_FLOAT, fUse);
}

void CRemoteCode::PushDouble(double d)
{
	double* dUse = new double;
	*dUse = d;
	PushParameter(PARAM_TYPE_DOUBLE, dUse);
}

void CRemoteCode::PushByte(unsigned char uc)
{
	unsigned char *ucUse = new unsigned char;
	*ucUse = uc;
	PushParameter(PARAM_TYPE_BYTE, &ucUse);
}

void CRemoteCode::PushPointer(void* ptr)
{
	PushParameter(PARAM_TYPE_POINTER, ptr);
}

void CRemoteCode::PushANSIString(const char* szString)
{
	PushParameter(PARAM_TYPE_STRING, (void*)szString);
}

void CRemoteCode::PushUNICODEString(const wchar_t* szString)
{
	PushParameter(PARAM_TYPE_WSTRING, (void*)szString);
}

void CRemoteCode::PushUNICODEStringStructure(UNICODE_STRING* ptrUnicodeString)
{
	PushParameter(PARAM_TYPE_UNICODE_STRUCT, (void*)ptrUnicodeString);
}

void CRemoteCode::LoadStringParam64(parameter_info_t paraminfo, parameter_index_t paramindex)
{
	if (paraminfo.ptype == PARAM_TYPE_STRING)
	{
		char* szParameter = (char*)paraminfo.pparam;

		string_alloc_t s;
		s.size = (ULONG)(strlen(szParameter) + 1);
		s.ptr = CommitMemory(szParameter, s.size);
		if (s.ptr == NULL)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("NULL Allocated ANSI string pointer....");
			#endif
			return;
		}

		m_CurrentInvokeInfo.strings.push_back(s);
		if (m_bIs64bit)
		{
			LoadParam64((unsigned __int64)s.ptr, paramindex);
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadStringType64] Not a 64 bit process!");
			#endif
		}
	}
	else if (paraminfo.ptype == PARAM_TYPE_WSTRING)
	{
		wchar_t *szParameter = (wchar_t *)paraminfo.pparam;

		string_alloc_t s;
		s.size = (ULONG)(wcslen(szParameter) * 2) + 1;
		s.ptr = CommitMemory(szParameter, s.size);
		if (s.ptr == NULL)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("NULL Allocated UNICODE string pointer....");
			#endif
			return;
		}

		m_CurrentInvokeInfo.strings.push_back(s);

		if (m_bIs64bit)
		{
			LoadParam64((unsigned __int64)s.ptr, paramindex);
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadStringType64] Not a 64 bit process!");
			#endif
		}
	}
	else if (paraminfo.ptype == PARAM_TYPE_UNICODE_STRUCT)
	{
		UNICODE_STRING unicodeParameter = *(UNICODE_STRING*)paraminfo.pparam;
		
		string_alloc_t s;
		s.size = (ULONG)(unicodeParameter.MaximumLength * 2) + 1;
		s.ptr = CommitMemory(unicodeParameter.Buffer, s.size);
		if (s.ptr == NULL)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("NULL Allocated UNICODE string pointer....");
			#endif
			return;
		}

		m_CurrentInvokeInfo.strings.push_back(s);

		UNICODE_STRING unicodeParamAlloc;
		unicodeParamAlloc.Buffer = (wchar_t*)s.ptr;
		unicodeParamAlloc.Length = unicodeParameter.Length;
		unicodeParamAlloc.MaximumLength = unicodeParameter.MaximumLength;

		struct_alloc_t unicodeStringAlloc;
		unicodeStringAlloc.size = (ULONG)sizeof(UNICODE_STRING);
		unicodeStringAlloc.ptr = CommitMemory(&unicodeParamAlloc, unicodeStringAlloc.size);

		m_CurrentInvokeInfo.structs.push_back(unicodeStringAlloc);

		if (m_bIs64bit)
		{
			LoadParam64((unsigned __int64)unicodeStringAlloc.ptr, paramindex);
		}
		else
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[LoadStringType64] Not a 64 bit process!");
			#endif
		}
	}
}

bool CRemoteCode::LoadParam64(unsigned __int64 pparam, parameter_index_t paramindex)
{
	switch (paramindex)
	{
	case PARAM_INDEX_RCX:
	{
		// mov  rcx, pparam
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xB9);
		AddLong64ToBuffer(pparam);

		break;
	}
	case PARAM_INDEX_RDX:
	{
		// mov  rdx, ulRdxParam
		AddByteToBuffer(0x48);
		AddByteToBuffer(0xBA);
		AddLong64ToBuffer(pparam);

		break;
	}
	case PARAM_INDEX_R8:
	{
		// mov  r8, ulR8Param
		AddByteToBuffer(0x49);
		AddByteToBuffer(0xB8);
		AddLong64ToBuffer(pparam);

		break;
	}
	case PARAM_INDEX_R9:
	{
		// mov  r9, ulR9Param
		AddByteToBuffer(0x49);
		AddByteToBuffer(0xB9);
		AddLong64ToBuffer(pparam);

		break;
	}
	default:
		return false;
	}
	return true;
}

void CRemoteCode::PushCall(calling_convention_t cconv, FARPROC CallAddress)
{
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("PushCall [%s][0x%IX]", CallingConventionToString(cconv).c_str(), CallAddress);
	#endif

	int iFunctionBegin = (int)m_CurrentInvokeInfo.params.size();

	m_CurrentInvokeInfo.calladdress = m_bIs64bit ? (unsigned __int64)CallAddress : (unsigned long)CallAddress;
	
	m_CurrentInvokeInfo.cconv = cconv;

	if ((m_bIs64bit || cconv == CCONV_WIN64) || cconv == CCONV_FASTCALL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Entering __fastcall");
		#endif

		if (m_bIs64bit) // 64 bit
		{
			////////////////////////////////////////////////////////////////////////////////////////////////
			//  First things first. 64 bit mandatory "shadow" space of at least 40 bytes for EVERY call   //
			//  Stack is 16 byte aligned. Every other param after rcx, rdx, r8, and r9 */				  //
			//  should be pushed onto the stack 														  //
			////////////////////////////////////////////////////////////////////////////////////////////////
			//
			// Reserve stack size (0x28 - minimal size for 4 registers and return address)
			// after call, stack must be aligned on 16 bytes boundary
			//
			size_t rsp_dif = (m_CurrentInvokeInfo.params.size() > 4) ? m_CurrentInvokeInfo.params.size() * sizeof(size_t) : 0x28;
			rsp_dif = Utils::Align(rsp_dif, 0x10);
			// sub  rsp, (rsp_dif + 8)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xEC);
			AddByteToBuffer((unsigned char)(rsp_dif + 8));

			if (iFunctionBegin > 0)
			{
				for (int i = 0; i < PARAM_INDEX_MAX; i++)
				{
					if (m_CurrentInvokeInfo.params.size() == 0)
						break;

					if (_PARAM_TYPE_STRING(m_CurrentInvokeInfo.params[0].ptype))
					{
						LoadStringParam64(m_CurrentInvokeInfo.params[0], (parameter_index_t)i);
					}
					else
					{
						unsigned __int64 param = *(unsigned __int64*)m_CurrentInvokeInfo.params[0].pparam; // rcx param
						LoadParam64(param, (parameter_index_t)i);
					}

					m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin());
				}
			}		

			PushAllParameters(true);

			//
			// Call function address, and clean stack
			//
			// mov  r13, calladdress
			// call r13
			AddByteToBuffer(0x49);
			AddByteToBuffer(0xBD);		//mov r13,
			AddLong64ToBuffer(m_CurrentInvokeInfo.calladdress); // calladdress
			AddByteToBuffer(0x41);
			AddByteToBuffer(0xFF);		//call
			AddByteToBuffer(0xD5);		//r13
			// Clean stack
			// add rsp, (rsp_dif + 8)
			AddByteToBuffer(0x48);
			AddByteToBuffer(0x83);
			AddByteToBuffer(0xC4);
			AddByteToBuffer((unsigned char)(rsp_dif + 8));
		}
		else // 32 bit
		{
			if (iFunctionBegin == 0)
			{
				PushCall(CCONV_STDCALL, CallAddress); // is actually a stdcall
				return;
			}
			else if (iFunctionBegin == 1)
			{
				unsigned long ulEdxParam = *(unsigned long*)m_CurrentInvokeInfo.params[0].pparam;
				// mov edx, ulEdxParam
				AddByteToBuffer(0xBA);
				AddLongToBuffer(ulEdxParam);

				m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin()); // erase edx param

				PushCall(CCONV_STDCALL, CallAddress); // is actually a stdcall

				return;
			}
			else // fastcall
			{
				unsigned long ulEdxParam = *(unsigned long *)m_CurrentInvokeInfo.params[0].pparam; // edx param
				unsigned long ulEaxParam = *(unsigned long *)m_CurrentInvokeInfo.params[1].pparam; // eax param
				//mov edx, ulEdxParam
				AddByteToBuffer(0xBA);
				AddLongToBuffer(ulEdxParam);
				//mov eax, ulEaxParam
				AddByteToBuffer(0xB8);
				AddLongToBuffer(ulEaxParam);

				m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin()); // erase edx (first) param
				m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin()); // erase eax (second) param

				PushAllParameters(true);

				//mov ebx, calladdress
				AddByteToBuffer(0xBB);
				AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.calladdress);
				//call ebx
				AddByteToBuffer(0xFF);
				AddByteToBuffer(0xD3);
			}
		}
	}
	else if (cconv == CCONV_CDECL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Entering __cdecl");
		#endif

		int iCalculateAddEsp = (iFunctionBegin * 4);

		bool rightToLeft = true;
		PushAllParameters(rightToLeft);

		//mov eax, calladdress
		AddByteToBuffer(0xB8);				
		AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.calladdress);
		//call eax
		AddByteToBuffer(0xFF);
		AddByteToBuffer(0xD0);

		if (iCalculateAddEsp != 0)
		{
			bool bUseByte = (iCalculateAddEsp <= 0xFF /* 255 */);
			if (bUseByte)
			{
				//add esp, (byte)iCalculateAddEsp
				AddByteToBuffer(0x83); // 0x83 is for adding a byte value
				AddByteToBuffer(0xC4);
				AddByteToBuffer((unsigned char)iCalculateAddEsp);
			}
			else
			{
				//add esp, iCalculateAddEsp
				AddByteToBuffer(0x81); // 0x81 is for adding a long value
				AddByteToBuffer(0xC4);
				AddLongToBuffer(iCalculateAddEsp);
			}
		}
	}
	else if (cconv == CCONV_STDCALL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Entering __stdcall");
		#endif

		bool rightToLeft = true;
		PushAllParameters(rightToLeft);

		//mov eax, calladdress
		//call eax
		AddByteToBuffer(0xB8);			//mov eax,						
		AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.calladdress); // calladdress	
		AddByteToBuffer(0xFF);			//call
		AddByteToBuffer(0xD0);			//eax
	}
	else if(cconv == CCONV_THISCALL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Entering __thiscall");
		#endif

		if (iFunctionBegin == 0) //no params...
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("No parameters passed for __thiscall, requires at least one parameter (ECX)");
			#endif
		}

		// first parameter of __thiscall is ALWAYS ECX. ALWAYS.
		// the parameter type should also be PARAM_TYPE_POINTER
		if (m_CurrentInvokeInfo.params[0].ptype != PARAM_TYPE_POINTER)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("Warning: \"THIS\" parameter type invalid [%i], should be PARAM_TYPE_POINTER", m_CurrentInvokeInfo.params[0].ptype);
			#endif
		}

		void *pThis = m_CurrentInvokeInfo.params[0].pparam;
		if (pThis == NULL)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("Warning: \"THIS\" parameter NULL for __thiscall function (ECX)");
			#endif
		}

		// mov ecx, ptr
		AddByteToBuffer(0x8B); // mov ecx,
		AddByteToBuffer(0x0D);
		AddLongToBuffer((unsigned long)pThis); // ptr

		// now we need to remove the first parameter from the vector, so when we execute the
		// parameter iteration function it is not included.....
		m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin());

		PushAllParameters(true);

		AddByteToBuffer(0xB8);			// mov eax, 
		AddLongToBuffer((unsigned long)m_CurrentInvokeInfo.calladdress); // calladdress
		AddByteToBuffer(0xFF);			// call
		AddByteToBuffer(0xD0);			// eax
	}

	//clear data
	m_CurrentInvokeInfo.params.clear();
	m_CurrentInvokeInfo.calladdress = NULL;
}

remote_thread_buffer_t CRemoteCode::GetRemoteThreadBuffer()
{
	return m_CurrentRemoteThreadBuffer;
}

bool CRemoteCode::ExecuteRemoteThreadBuffer(remote_thread_buffer_t thread_data, bool async)
{
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShoutBufferHex();
	#endif

	void* RemoteBuffer = NULL;

	unsigned char *newBuffer = new unsigned char[thread_data.size()];

	for (int i = 0; i < (int)thread_data.size(); i++)
		newBuffer[i] = thread_data[i];

	RemoteBuffer = CommitMemory(newBuffer, thread_data.size());

	delete[] newBuffer;

	if (RemoteBuffer == NULL)
		return false;

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("RemoteBuffer: 0x%IX\n", RemoteBuffer);
	#endif

	HANDLE hThreadHandle = CreateRemoteThreadInProcess((LPTHREAD_START_ROUTINE)RemoteBuffer, NULL); 
	if (hThreadHandle == INVALID_HANDLE_VALUE)
	{
		RemoteFreeMemory(RemoteBuffer, thread_data.size());
		// Destroy remote buffer for next one
		DestroyRemoteThreadBuffer();

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Failed to execute remote buffer in process 0x%X", m_hProcess);
		#endif
		return false;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("Remote Buffer Executed in process 0x%X", m_hProcess);
	#endif

	if (async)
		WaitForSingleObject(hThreadHandle, INFINITE);

	RemoteFreeMemory(RemoteBuffer, thread_data.size());

	// Destroy remote buffer for next one
	DestroyRemoteThreadBuffer();

	return true;
}

void CRemoteCode::DestroyRemoteThreadBuffer()
{
	// Free remote strings
	for (size_t i = 0; i < m_CurrentInvokeInfo.strings.size(); i++)
		RemoteFreeMemory(m_CurrentInvokeInfo.strings[i].ptr, m_CurrentInvokeInfo.strings[i].size);
	// Free remote structs
	for (size_t i = 0; i < m_CurrentInvokeInfo.structs.size(); i++)
		RemoteFreeMemory(m_CurrentInvokeInfo.structs[i].ptr, m_CurrentInvokeInfo.structs[i].size);

	m_CurrentInvokeInfo.calladdress = 0;
	m_CurrentInvokeInfo.params.clear();
	m_CurrentRemoteThreadBuffer.clear();
}

HANDLE CRemoteCode::CreateRemoteThreadInProcess(LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam)
{
	return Utils::NtCreateThreadEx(m_hProcess, lpThread, lpParam, NULL);
	//return CreateRemoteThread(m_hProcess, NULL, NULL, lpThread, lpParam, NULL, NULL);
}

void CRemoteCode::BeginCall64()
{
	// backup param registers

	// mov    QWORD PTR [rsp+0x8],rcx
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x4C); 
	AddByteToBuffer(0x24);
	AddByteToBuffer(1 * sizeof(size_t));
	// mov    QWORD PTR [rsp+0x10],rdx
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x54);
	AddByteToBuffer(0x24);
	AddByteToBuffer(2 * sizeof(size_t));
	// mov    QWORD PTR [rsp+0x18],r8
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x44);
	AddByteToBuffer(0x24);
	AddByteToBuffer(3 * sizeof(size_t));
	// mov    QWORD PTR [rsp+0x8],rcx
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x24);
	AddByteToBuffer(4 * sizeof(size_t));
}

void CRemoteCode::EndCall64()
{
	// Restore registers and return

	// mov    rcx,QWORD PTR [rsp+0x8]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x24);
	AddByteToBuffer(1 * sizeof(size_t));
	// mov    rdx,QWORD PTR [rsp+0x10]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x54);
	AddByteToBuffer(0x24);
	AddByteToBuffer(2 * sizeof(size_t));
	// mov    r8,QWORD PTR [rsp+0x18]
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x44);
	AddByteToBuffer(0x24);
	AddByteToBuffer(3 * sizeof(size_t));
	// mov    r9,QWORD PTR [rsp+0x20]
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x8B);
	AddByteToBuffer(0x4C);
	AddByteToBuffer(0x24);
	AddByteToBuffer(4 * sizeof(size_t));
	// ret
	AddByteToBuffer(0xC3);
}

void CRemoteCode::AddByteToBuffer(unsigned char in)
{
	//#ifdef DEBUG_MESSAGES_ENABLED
	//DebugShout("Byte added to buffer: 0x%.2X", in);
	//#endif
	m_CurrentRemoteThreadBuffer.push_back(in);
}

void CRemoteCode::AddLongToBuffer(unsigned long in)
{
	WORD LoWord = LOWORD(in); // Reversing the long by bytes for buffer
	WORD HiWord = HIWORD(in);

	AddByteToBuffer(LOBYTE(LoWord));
	AddByteToBuffer(HIBYTE(LoWord));
	AddByteToBuffer(LOBYTE(HiWord));
	AddByteToBuffer(HIBYTE(HiWord));
}

void CRemoteCode::AddLong64ToBuffer(unsigned __int64 in)
{
	unsigned long lowInt32 = (unsigned long)in;
	unsigned long highInt32 = (unsigned long)(in >> 32);

	AddLongToBuffer(lowInt32);
	AddLongToBuffer(highInt32);
}

void CRemoteCode::PushAllParameters(bool right_to_left)
{
	if (m_CurrentInvokeInfo.params.size() == 0)
		return;

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("Number of parameters for function [%i]", m_CurrentInvokeInfo.params.size());
	#endif

	vector<parameter_info_t> currentParams = m_CurrentInvokeInfo.params;
	vector<parameter_info_t> pushOrder;

	if (right_to_left == false)
	{
		//left-to-right
		for (int i = 0; i < (int)m_CurrentInvokeInfo.params.size(); i++)
		{
			pushOrder.push_back(m_CurrentInvokeInfo.params.at(i));

			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("Parameter found [%i][%s]", i, ParameterTypeToString(m_CurrentInvokeInfo.params.at(i).ptype).c_str());
			#endif
		}
	}
	else
	{
		//right-to-left
		if (m_CurrentInvokeInfo.params.size() == 1)
		{
			pushOrder.push_back(m_CurrentInvokeInfo.params.at(0));
			
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("Parameter found [%i][%s]", 0, ParameterTypeToString(m_CurrentInvokeInfo.params.at(0).ptype).c_str());
			#endif
		}
		else
		{
			int iBegin = (int)m_CurrentInvokeInfo.params.size() - 1;
			while (iBegin != -1)
			{
				pushOrder.push_back(m_CurrentInvokeInfo.params.at(iBegin));
				
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("Parameter found [%i][%s]", iBegin, ParameterTypeToString(m_CurrentInvokeInfo.params.at(iBegin).ptype).c_str());
				#endif

				iBegin--;
			}
		}
	}

	for (int p = 0; p < (int)pushOrder.size(); p++)
	{
		parameter_info_t *paraminfo = &pushOrder[p];
		if (paraminfo == NULL)
			continue;

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Function Iter [%i] Parameter [%s]", p, ParameterTypeToString(paraminfo->ptype).c_str());
		#endif

		if (paraminfo->pparam == NULL)
		{
			// push 0
			AddByteToBuffer(0x68);	// push
			AddLongToBuffer(0x00);	// 0
			continue;
		}

		switch (paraminfo->ptype)
		{
		case PARAM_TYPE_DOUBLE:		// all the same shit 8 bytes
		case PARAM_TYPE_INT64:		//
		{
			if (paraminfo->pparam)
			{
				unsigned __int64 ulParam = *(unsigned __int64 *)paraminfo->pparam;

				if (m_bIs64bit)
				{
					// mov rax, ulParam
					// push rax
					AddByteToBuffer(0x48);
					AddByteToBuffer(0xB8);
					AddLong64ToBuffer(ulParam);
					AddByteToBuffer(0x50);
				}
				else
				{
					// ill do this later
					unsigned long ulParam = *(unsigned long *)paraminfo->pparam;
					// push ulParam
					AddByteToBuffer(0x68);
					AddLongToBuffer(ulParam);
				}
			}
			else
			{
				// if it is PARAM_TYPE_POINTER with a NULL pointer
				// we don't want to crash
				// push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(0x00);
			}
			break;
		}
		case PARAM_TYPE_POINTER:	//
		{
			if (paraminfo->pparam)
			{
				unsigned __int64 ulParam = *(unsigned __int64*)paraminfo->pparam;

				if (m_bIs64bit)
				{
					// mov rax, ulParam
					AddByteToBuffer(0x48);
					AddByteToBuffer(0xB8);
					AddLong64ToBuffer(ulParam);
					// push rax
					AddByteToBuffer(0x50);
				}
				else
				{
					unsigned long ulParam = *(unsigned long *)paraminfo->pparam;
					// push ulParam
					AddByteToBuffer(0x68);
					AddLongToBuffer(ulParam);
				}
			}
			else
			{
				// if it is PARAM_TYPE_POINTER with a NULL pointer
				// we don't want to crash
				// push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(0x00);
			}
			break;
		}
		case PARAM_TYPE_SHORT:		// all the same shit 4 bytes
		case PARAM_TYPE_INT:		//
		case PARAM_TYPE_FLOAT:		//
		{
			if (paraminfo->pparam)
			{
				unsigned long ulParam = *(unsigned long *)paraminfo->pparam;

				// push ulParam
				AddByteToBuffer(0x68);
				AddLongToBuffer(ulParam);
			}
			else
			{
				// if it is PARAM_TYPE_POINTER with a NULL pointer
				// we don't want to crash
				// push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(NULL);
			}

			break;
		}
		case PARAM_TYPE_BYTE:
		{
			unsigned char ucParam = *(unsigned char*)paraminfo->pparam;

			// push ucParam
			AddByteToBuffer(0x6A); // 0x6A is for pushing bytes
			AddByteToBuffer(ucParam);

			break;
		}
		case PARAM_TYPE_BOOL:
		{
			bool bParam = *(bool*)paraminfo->pparam;

			unsigned char ucParam = (bParam) ? 1 : 0;

			// push ucParam
			AddByteToBuffer(0x6A);
			AddByteToBuffer(ucParam);

			break;
		}
		case PARAM_TYPE_STRING:
		{
			char* szParameter = (char*)paraminfo->pparam;

			string_alloc_t s;
			s.size = (ULONG)(strlen(szParameter) + 1);
			s.ptr = CommitMemory(szParameter, s.size);
			if (s.ptr == NULL)
			{
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("NULL Allocated ANSI string pointer....");
				#endif
				continue; // bad beans
			}

			m_CurrentInvokeInfo.strings.push_back(s);
			if (m_bIs64bit)
			{
				// mov rax, s.ptr
				AddByteToBuffer(0x48);
				AddByteToBuffer(0xB8);
				AddLong64ToBuffer((unsigned __int64)s.ptr);
				// push rax
				AddByteToBuffer(0x50);
			}
			else
			{
				// push s.ptr
				AddByteToBuffer(0x68);
				AddLongToBuffer((unsigned long)s.ptr);
			}

			break;
		}
		case PARAM_TYPE_WSTRING:
		{
			wchar_t *szParameter = (wchar_t *)paraminfo->pparam;

			string_alloc_t s;
			s.size = (ULONG)(wcslen(szParameter) * 2) + 1;
			s.ptr = CommitMemory(szParameter, s.size);
			if (s.ptr == NULL)
			{
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("NULL Allocated UNICODE string pointer....");
				#endif
				continue; //bad beans
			}

			m_CurrentInvokeInfo.strings.push_back(s);

			if (m_bIs64bit)
			{
				// mov rax, s.ptr			
				AddByteToBuffer(0x48);
				AddByteToBuffer(0xB8);
				AddLong64ToBuffer((unsigned __int64)s.ptr);
				// push rax
				AddByteToBuffer(0x50);
			}
			else
			{
				// push s.ptr
				AddByteToBuffer(0x68);
				AddLongToBuffer((unsigned long)s.ptr);
			}

			break;
		}
		case PARAM_TYPE_UNICODE_STRUCT:
		{
			UNICODE_STRING unicodeParameter = *(UNICODE_STRING*)paraminfo->pparam;
		
			string_alloc_t s;
			s.size = (ULONG)(unicodeParameter.MaximumLength * 2) + 1;
			s.ptr = CommitMemory(unicodeParameter.Buffer, s.size);
			if (s.ptr == NULL)
			{
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("NULL Allocated UNICODE string pointer....");
				#endif
				return;
			}

			m_CurrentInvokeInfo.strings.push_back(s);

			UNICODE_STRING unicodeParamAlloc;
			unicodeParamAlloc.Buffer = (wchar_t*)s.ptr;
			unicodeParamAlloc.Length = unicodeParameter.Length;
			unicodeParamAlloc.MaximumLength = unicodeParameter.MaximumLength;

			struct_alloc_t unicodeStringAlloc;
			unicodeStringAlloc.size = (ULONG)sizeof(UNICODE_STRING);
			unicodeStringAlloc.ptr = CommitMemory(&unicodeParamAlloc, unicodeStringAlloc.size);

			m_CurrentInvokeInfo.structs.push_back(unicodeStringAlloc);

			// push unicodeStringAlloc.ptr
			AddByteToBuffer(0x68);
			AddLongToBuffer((unsigned long)unicodeStringAlloc.ptr);
		}
		default:
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("Unable to locate parameter type %i", paraminfo->ptype);
			#endif

			break;
		}

		} //end of switch statement
	}
}

DWORD CRemoteCode::CreateRPCEnvironment(bool noThread /*= false*/)
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD thdID = 1337;
	bool status = true;

	// Allocate environment codecave
	if (m_pWorkerCode == nullptr)
		m_pWorkerCode = RemoteAllocateMemory(0x1000);

	// Create RPC thread
	if (noThread == false)
		thdID = CreateWorkerThread();

	// Create synchronization event
	status = CreateAPCEvent(thdID);
	if (thdID == 0 || status == false)
		dwResult = GetLastError();

	return dwResult;
}


/*
Create thread for RPC

RETURN:
Thread ID
*/
DWORD CRemoteCode::CreateWorkerThread()
{
	DWORD thdID = 0;
	int space = 4 * sizeof(size_t); // 4 int64 values on top of thread. Kinda likea mini stack

	//
	// Create execution thread
	//
	if (!m_hWorkThd)
	{
		/*
		for(;;)
		SleepEx(5, TRUE);

		ExitThread(SetEvent(m_hWaitEvent));
		*/
		BeginCall64();

		PushUInt64(5);
		PushUInt64(TRUE);
		PushCall(CCONV_WIN64, (FARPROC)SleepEx);

		// Relative jump back RIP 41 bytes
		AddByteToBuffer(0xEB);
		AddByteToBuffer(0xD5);

		ExitThreadWithStatus();

		EndCall64();

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShoutBufferHex();
		#endif

		unsigned char *newBuffer = new unsigned char[m_CurrentRemoteThreadBuffer.size()];

		for (int i = 0; i < (int)m_CurrentRemoteThreadBuffer.size(); i++)
			newBuffer[i] = m_CurrentRemoteThreadBuffer[i];

		m_dwWorkerCodeSize = m_CurrentRemoteThreadBuffer.size();
		m_pWorkerCodeThread = (void*)((size_t)m_pWorkerCode + space);
		m_pUserCode = (void*)((size_t)m_pWorkerCodeThread + m_dwWorkerCodeSize);

		BOOL bWrite = WriteProcessMemory(m_hProcess, (void*)m_pWorkerCodeThread, newBuffer, m_dwWorkerCodeSize, NULL);
		if (bWrite == FALSE)
		{
			delete[] newBuffer;

			// Destroy remote buffer for next one
			DestroyRemoteThreadBuffer();

			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[CreateWorkerThread] Failed to allocate m_pWorkerCode!");
			#endif
			return NULL;
		}

		delete[] newBuffer;


		//m_hWorkThd = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)m_pWorkerCodeThread, m_pWorkerCode, 0, &thdID);
		m_hWorkThd = Utils::NtCreateThreadEx(m_hProcess, (LPTHREAD_START_ROUTINE)m_pWorkerCodeThread, m_pWorkerCode, &thdID);

		// Destroy remote buffer for next one
		DestroyRemoteThreadBuffer();

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("[CreateWorkerThread] Worker thread ID: %d ", GetThreadId(m_hWorkThd));
		#endif

		return thdID;
	}
	else
		return GetThreadId(m_hWorkThd);
}

DWORD CRemoteCode::TerminateWorkerThread()
{
	if (m_hWaitEvent)
	{
		CloseHandle(m_hWaitEvent);
		m_hWaitEvent = NULL;
	}

	if (m_hWorkThd)
	{
		BOOL res = TerminateThread(m_hWorkThd, 0);
		m_hWorkThd = NULL;

		if (m_pWorkerCode)
		{
			RemoteFreeMemory(m_pWorkerCode, 0x1000);
			m_pWorkerCode = nullptr;
		}

		return res == TRUE;
	}
	else
		return ERROR_SUCCESS;
}

bool CRemoteCode::CreateAPCEvent( DWORD threadID )
{         
    if(m_hWaitEvent == NULL)
    {
        size_t dwResult        = ERROR_SUCCESS;
		void* pCodecave		   = NULL;
        wchar_t pEventName[64] = {0};
        size_t len             =  sizeof(pEventName);

        // Generate event name
        swprintf_s(pEventName, ARRAYSIZE(pEventName), L"_INJEvent_0x%X_0x%X", threadID, GetTickCount());

		BeginCall64();

		PushUInt64(NULL);	// lpEventAttributes
		PushUInt64(TRUE);	// bManualReset
		PushUInt64(FALSE);	// bInitialState
		PushUNICODEString(pEventName); // lpName
        PushCall(CCONV_WIN64, (FARPROC)CreateEventW);

        // Save event handle
		#ifdef _WIN64
		// mov  rdx, [rsp + 8]
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x8B);
		AddByteToBuffer(0x54);
		AddByteToBuffer(0x24); 
		AddByteToBuffer(sizeof(size_t));
		#else
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x8B);
		AddByteToBuffer(0x54);
		AddByteToBuffer(0x24);
		AddByteToBuffer(sizeof(size_t));
        //a.mov(AsmJit::ndx, AsmJit::dword_ptr(AsmJit::nbp, 2 * WordSize));
		#endif   

		// mov  [rdx+0x8], rax
		AddByteToBuffer(0x48);
		AddByteToBuffer(0x89);
		AddByteToBuffer(0x42);
		AddByteToBuffer(sizeof(size_t));
		//a.mov(sysint_ptr(AsmJit::ndx, WordSize), AsmJit::nax);

        ExitThreadWithStatus();

		EndCall64();

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShoutBufferHex();
		#endif

		unsigned char *newBuffer = new unsigned char[m_CurrentRemoteThreadBuffer.size()];

		for (int i = 0; i < (int)m_CurrentRemoteThreadBuffer.size(); i++)
			newBuffer[i] = m_CurrentRemoteThreadBuffer[i];

		pCodecave = CommitMemory(newBuffer, m_CurrentRemoteThreadBuffer.size());

		delete[] newBuffer;

		if (pCodecave == NULL)
		{
			// Destroy remote buffer for next one
			DestroyRemoteThreadBuffer();

			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("[CreateAPCEvent] Failed to allocate pCodecave!");
			#endif
			return NULL;
		}

		HANDLE hThread = Utils::NtCreateThreadEx(m_hProcess, (LPTHREAD_START_ROUTINE)pCodecave, m_pWorkerCode, NULL);
		if (hThread)
		{
			WaitForSingleObject(hThread, INFINITE);
			// TODO: Need to find something better for 64-bit results
			if (GetExitCodeThread(hThread, (LPDWORD)&dwResult) == 0)
			{
				#ifdef DEBUG_MESSAGES_ENABLED
				DebugShout("[CreateAPCEvent] Failed to get hThread Exit Code! Error: 0x%X", GetLastError());
				#endif
			}

		}

        m_hWaitEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, pEventName);

		if (pCodecave)
			RemoteFreeMemory(pCodecave, m_CurrentRemoteThreadBuffer.size());

		// Destroy remote buffer for next one
		DestroyRemoteThreadBuffer();

        if(dwResult == NULL || m_hWaitEvent == NULL)
        {
            SetLastError(ERROR_OBJECT_NOT_FOUND);
            return false;
        }
    }

    return true;
}

bool CRemoteCode::CreateActxFromManifest(const char* Manifest)
{
	size_t  result = 0;
	ACTCTX  act = { 0 };

	m_pAContext = RemoteAllocateMemory(512);

	act.cbSize = sizeof(act);
	// set the source as the temporary manifest file that we extracted using the pe info
	act.lpSource = (LPCSTR)((SIZE_T)m_pAContext + sizeof(HANDLE) + sizeof(act)); 

	BeginCall64();

	// CreateActCtx(&act)
	PushInt64((unsigned __int64)((size_t)m_pAContext + sizeof(HANDLE)));
	PushCall(CCONV_WIN64, (FARPROC)CreateActCtx);
	// pTopImage->pAContext = CreateActCtx(&act)
	// mov rdx, m_pAContext
	AddByteToBuffer(0x48);
	AddByteToBuffer(0xBA);
	AddLong64ToBuffer((unsigned __int64)m_pAContext);
	// mov [rdx], rax
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x02);

	SaveRetValAndSignalEvent();

	EndCall64();

	if (WriteProcessMemory(m_hProcess, (BYTE*)m_pAContext + sizeof(HANDLE), &act, sizeof(act), NULL))
	{
		if (WriteProcessMemory(m_hProcess, (BYTE*)m_pAContext + sizeof(HANDLE) + sizeof(act), (void*)Manifest, strlen(Manifest) + 1, NULL))
		{
			if (ExecuteInWorkerThread(m_CurrentRemoteThreadBuffer, result) != ERROR_SUCCESS || (HANDLE)result == INVALID_HANDLE_VALUE)
			{
				if (m_pAContext)
				{
					RemoteFreeMemory(m_pAContext, 512);
					m_pAContext = nullptr;
				}

				SetLastError(100204);
				return false;
			}
		}
	}
	else
		return false;

	return true;
}

DWORD CRemoteCode::ExecuteInWorkerThread(remote_thread_buffer_t thread_data, size_t& callResult)
{
	DWORD dwResult = ERROR_SUCCESS;

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShoutBufferHex();
	#endif

	void* RemoteBuffer = NULL;

	unsigned char *newBuffer = new unsigned char[thread_data.size()];

	for (int i = 0; i < (int)thread_data.size(); i++)
		newBuffer[i] = thread_data[i];

	// Write code
	RemoteBuffer = CommitMemory(newBuffer, thread_data.size());

	delete[] newBuffer;

	if (RemoteBuffer == NULL)
		return false;

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("RemoteBuffer: 0x%IX\n", RemoteBuffer);
	#endif

	// Create thread if needed
	if (!m_hWorkThd)
		CreateRPCEnvironment();

	// Reset wait event
	if (m_hWaitEvent)
		ResetEvent(m_hWaitEvent);

	// Execute code in thread context
	if (QueueUserAPC((PAPCFUNC)RemoteBuffer, m_hWorkThd, (ULONG_PTR)m_pWorkerCode))
	{
		dwResult = WaitForSingleObject(m_hWaitEvent, INFINITE);
		ReadProcessMemory(m_hProcess, m_pWorkerCode, &callResult, sizeof(size_t), NULL);
	}

	// Ensure APC function fully returns
	Sleep(10);

	// Free remote memory. Don't wanna forget lel
	RemoteFreeMemory(RemoteBuffer, thread_data.size());

	// Destroy remote buffer for next one
	DestroyRemoteThreadBuffer();

	return dwResult;
}

void CRemoteCode::ExitThreadWithStatus()
{
	// mov  rcx, rax
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89); 
	AddByteToBuffer(0xC1);
	// mov  r13, [ExitThread]
	AddByteToBuffer(0x49);
	AddByteToBuffer(0xBD);
	AddLong64ToBuffer((INT_PTR)ExitThread);
	// call r13
	AddByteToBuffer(0x41);
	AddByteToBuffer(0xFF); 
	AddByteToBuffer(0xD5);
}

//
// Signal wait event. If it's not signaled, 
// then the call will not disengage from the thread
//
void CRemoteCode::SaveRetValAndSignalEvent()
{
	// mov rdx, [rsp + 0x8]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B); 
	AddByteToBuffer(0x54);
	AddByteToBuffer(0x24); 
	AddByteToBuffer(0x08);
	// mov [rdx], rax
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x89);
	AddByteToBuffer(0x02);

	// SetEvent(hEvent)
	// mov rcx, [rdx + 0x8]
	AddByteToBuffer(0x48);
	AddByteToBuffer(0x8B); 
	AddByteToBuffer(0x4A); 
	AddByteToBuffer(0x08);
	// mov r13, SetEvent
	AddByteToBuffer(0x49);
	AddByteToBuffer(0xBD);
	AddLong64ToBuffer((INT_PTR)SetEvent);
	// call r13
	AddByteToBuffer(0x41);
	AddByteToBuffer(0xFF);
	AddByteToBuffer(0xD5);
}

void* CRemoteCode::CommitMemory(void *data, SIZE_T size_of_data)
{
	void *pPointer = RemoteAllocateMemory(size_of_data);
	if (pPointer == NULL) 
		return NULL;

	BOOL bWrite = WriteProcessMemory(m_hProcess, pPointer, data, size_of_data, NULL);
	if (bWrite == FALSE) 
		return NULL;

	return pPointer;
}

void* CRemoteCode::RemoteAllocateMemory(SIZE_T size)
{
	return VirtualAllocEx(m_hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void CRemoteCode::RemoteFreeMemory(void *address, SIZE_T size)
{
	VirtualFreeEx(m_hProcess, address, size, MEM_RELEASE);
}

string CRemoteCode::CallingConventionToString(calling_convention_t cconv)
{
	static const char *szCconvTypes[] = {
		"CCONV_CDECL",
		"CCONV_STDCALL",
		"CCONV_THISCALL",
		"CCONV_FASTCALL",
		"CCONV_WIN64"
	};
	return szCconvTypes[cconv];
}

string CRemoteCode::ParameterTypeToString(parameter_type_t type)
{
	static const char *szParameterTypes[] = {
		"PARAM_TYPE_INT",
		"PARAM_TYPE_INT64",
		"PARAM_TYPE_BOOL",
		"PARAM_TYPE_SHORT",
		"PARAM_TYPE_FLOAT",
		"PARAM_TYPE_DOUBLE",
		"PARAM_TYPE_BYTE",
		"PARAM_TYPE_POINTER",
		"PARAM_TYPE_STRING",
		"PARAM_TYPE_WSTRING",
		"PARAM_TYPE_UNICODE_STRUCT"
	};
	
	return szParameterTypes[type];
}

bool CRemoteCode::SetBaseDirectory()
{
	if (m_bBaseDirIsSet)
		return true;

	char szAppDataPath[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, szAppDataPath)))
	{
		char* lastDirectorySlash = strrchr(szAppDataPath, '\\');
		*(++lastDirectorySlash) = '\0';

		strcpy_s(m_baseDir, szAppDataPath);
		strcat_s(m_baseDir, "Local\\injectora\\");

		if (!Utils::DoesDirectoryExist(m_baseDir))
			CreateDirectory(m_baseDir, NULL);

		m_bBaseDirIsSet = true;

		return true;
	}

	return false;
}

#ifdef DEBUG_MESSAGES_ENABLED
void CRemoteCode::DebugShout(const char *fmt, ...)
{
	static bool doneOnce = false;
	if (!doneOnce)
	{
		if (SetBaseDirectory())
		{
			strcpy_s(m_infoLog, m_baseDir);
			strcat_s(m_infoLog, "injectora.log");

			const time_t now = time(0);

			tm timeStruct;
			localtime_s(&timeStruct, &now);

			char timeBuffer[80]; char outTimeBuffer[80];
			strftime(timeBuffer, sizeof(timeBuffer), "%m\\%d\\%Y %X", &timeStruct);
			_snprintf_s(outTimeBuffer, sizeof(outTimeBuffer), "\nINJECTORA\n%s\n\n", timeBuffer);

			OutputDebugString(outTimeBuffer);

			m_logFile.open(m_infoLog, ios::out | ios::trunc);
			m_logFile << "INJECTORA" << std::endl << timeBuffer << std::endl << std::endl;
			m_logFile.close();

			doneOnce = true;
		}
	}

	if (!m_bBaseDirIsSet)
		return;

	char *va_args;
	char szLogBuffer[512];

	va_start(va_args, fmt);
	if (_vsnprintf_s(szLogBuffer, sizeof(szLogBuffer), _TRUNCATE, fmt, va_args) == -1)
		szLogBuffer[sizeof(szLogBuffer) - 1] = '\0';
	va_end(va_args);

	size_t len = strlen(szLogBuffer);

	char* szNewLogBuffer = new char[len + 2];

	strcpy_s(szNewLogBuffer, len + 2, szLogBuffer);

	szNewLogBuffer[len] = '\n';
	szNewLogBuffer[len + 1] = '\0';

	OutputDebugString(szNewLogBuffer);
	
	m_logFile.open(m_infoLog, ios::out | ios::app);

	if (m_logFile.is_open())
	{
		m_logFile << szNewLogBuffer;

		m_logFile.close();
	}

	if (szNewLogBuffer)
		free(szNewLogBuffer);
}

void CRemoteCode::DebugShoutBufferHex()
{
	if (!m_bBaseDirIsSet)
		return;

	m_logFile.open(m_infoLog, ios::out | ios::app);

	int count = 1;

	m_logFile << "RemoteThreadBuffer:";
	m_logFile << std::endl << " offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" 
			  << std::endl << "--------|------------------------------------------------"
			  << std::endl << "00000000| ";

	OutputDebugString("\n offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n--------|------------------------------------------------\n00000000| ");

	std::string buf, minifiedBuf;

	for (size_t i = 0; i < m_CurrentRemoteThreadBuffer.size(); i++)
	{
		char szCurrentHexMinified[128] = { 0 };
		sprintf_s(szCurrentHexMinified, "%.2X ", m_CurrentRemoteThreadBuffer[i]);
		minifiedBuf += szCurrentHexMinified;

		char szCurrentHex[128] = { 0 };
		if (count % 16 == 0 && count != 1)
		{
			sprintf_s(szCurrentHex, "%.2X\n%.8X| ", m_CurrentRemoteThreadBuffer[i], count);
			//printf_s("%.2X\n%.8X| ", m_CurrentRemoteThreadBuffer[i], count);
		}
		else
		{
			sprintf_s(szCurrentHex, "%.2X ", m_CurrentRemoteThreadBuffer[i]);
			//printf_s("%.2X ", m_CurrentRemoteThreadBuffer[i]);
		}

		buf += szCurrentHex;
		count++;
	}

	m_logFile << buf.c_str() << std::endl;

	m_logFile.close();

	buf.append("\n\n");
	OutputDebugString(buf.c_str());

	minifiedBuf.append("\n\n");
	OutputDebugString(minifiedBuf.c_str());
}
#endif
