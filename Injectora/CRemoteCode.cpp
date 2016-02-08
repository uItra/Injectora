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
	DebugShout("Adding parameter to function [%i][0x%X]", pi.ptype, pi.pparam);
	#endif

	m_CurrentInvokeInfo.params.push_back(pi);
}

void CRemoteCode::PushInt(int i)
{
	int *iUse = new int;
	*iUse = i;
	PushParameter(PARAMETER_TYPE_INT, iUse);
}

void CRemoteCode::PushInt64(__int64 i)
{
	__int64 *iUse = new __int64;
	*iUse = i;
	PushParameter(PARAMETER_TYPE_INT64, iUse);
}

void CRemoteCode::PushBool(bool b)
{
	bool *bUse = new bool;
	*bUse = b;
	PushParameter(PARAMETER_TYPE_BOOL, bUse);
}

void CRemoteCode::PushShort(short s)
{
	short *sUse = new short;
	*sUse = s;
	PushParameter(PARAMETER_TYPE_SHORT, sUse);
}

void CRemoteCode::PushFloat(float f)
{
	float *fUse = new float;
	*fUse = f;
	PushParameter(PARAMETER_TYPE_FLOAT, fUse);
}

void CRemoteCode::PushDouble(double d)
{
	double* dUse = new double;
	*dUse = d;
	PushParameter(PARAMETER_TYPE_DOUBLE, dUse);
}

void CRemoteCode::PushByte(unsigned char uc)
{
	unsigned char *ucUse = new unsigned char;
	*ucUse = uc;
	PushParameter(PARAMETER_TYPE_BYTE, &ucUse);
}

void CRemoteCode::PushPointer(void* ptr)
{
	PushParameter(PARAMETER_TYPE_POINTER, ptr);
}

void CRemoteCode::PushANSIString(const char* szString)
{
	PushParameter(PARAMETER_TYPE_STRING, (void*)szString);
}

void CRemoteCode::PushUNICODEString(const wchar_t* szString)
{
	PushParameter(PARAMETER_TYPE_WSTRING, (void*)szString);
}

void CRemoteCode::PushCall(calling_convention_t cconv, FARPROC CallAddress)
{
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("PushCall [%s][0x%X]", CallingConventionToString(cconv).c_str(), CallAddress);
	#endif

	int iFunctionBegin = (int)m_CurrentInvokeInfo.params.size();

	if (m_bIs64bit)
		m_CurrentInvokeInfo.calladdress = (unsigned __int64)CallAddress;
	else
		m_CurrentInvokeInfo.calladdress = (unsigned long)CallAddress;
	
	m_CurrentInvokeInfo.cconv = cconv;

	if (m_bIs64bit || cconv == CCONV_FASTCALL)
	{
		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Entering __fastcall");
		#endif

		if (m_bIs64bit) // 64 bit
		{
			/* Backup parameter register RCX, RDX, R8, and R9 onto stack */
			Prologue64();

			////////////////////////////////////////////////////////////////////////////////////////////////
			/// First things first. 64 bit mandatory "shadow" space of at least 32 bytes for EVERY call *///
			/// Stack is 16 byte aligned. Every other param after rcx, rdx, r8, and r9 */				 ///
			/// should be pushed onto the stack */														 ///
			////////////////////////////////////////////////////////////////////////////////////////////////

			//
			// reserve stack size (0x28 - minimal size for 4 registers and return address)
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
				if (m_CurrentInvokeInfo.params[0].pparam)
				{
					unsigned __int64 ulRcxParam = *(unsigned __int64*)m_CurrentInvokeInfo.params[0].pparam; // rcx param
					// mov  rcx, ulRcxParam
					AddByteToBuffer(0x48);
					AddByteToBuffer(0xB9);			// mov  rcx, ulRcxParam
					AddLong64ToBuffer(ulRcxParam);	// 

					// erase rcx param
					m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin());

					if (m_CurrentInvokeInfo.params.size() > 0)
					{
						if (m_CurrentInvokeInfo.params[0].pparam)
						{
							unsigned __int64 ulRdxParam = *(unsigned __int64*)m_CurrentInvokeInfo.params[0].pparam; // rdx param
							// mov  rdx, ulRdxParam
							AddByteToBuffer(0x48);
							AddByteToBuffer(0xBA);			// mov  rdx, ulRdxParam
							AddLong64ToBuffer(ulRdxParam);	// 

							// erase rdx param
							m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin());

							if (m_CurrentInvokeInfo.params.size() > 0)
							{
								if (m_CurrentInvokeInfo.params[0].pparam)
								{
									unsigned __int64 ulR8Param = *(unsigned __int64*)m_CurrentInvokeInfo.params[0].pparam; // r8 param
									// mov  r8, ulR8Param
									AddByteToBuffer(0x49);
									AddByteToBuffer(0xB8);			// mov  r8, ulR8Param
									AddLong64ToBuffer(ulR8Param);	// 

									// erase r8 param
									m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin());

									if (m_CurrentInvokeInfo.params.size() > 0)
									{
										if (m_CurrentInvokeInfo.params[0].pparam)
										{
											unsigned __int64 ulR9Param = *(unsigned __int64*)m_CurrentInvokeInfo.params[0].pparam; // r9 param
											// mov  r9, ulR9Param
											AddByteToBuffer(0x49);
											AddByteToBuffer(0xB9);			// mov  r9, ulR9Param
											AddLong64ToBuffer(ulR9Param);	// 

											// erase r9 param
											m_CurrentInvokeInfo.params.erase(m_CurrentInvokeInfo.params.begin());

										} // ulR9Param
									}
								} // ulR8Param
							}
						} // ulRdxParam
					}		
				} // ulRcxParam
			}		

			//
			// Call function address, and clean stack
			//
			// mov  rax, calladdress
			// call rax
			AddByteToBuffer(0x48);
			AddByteToBuffer(0xB8);		//mov rax,
			AddLong64ToBuffer(m_CurrentInvokeInfo.calladdress); // calladdress
			AddByteToBuffer(0xFF);		//call
			AddByteToBuffer(0xD0);		//rax
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
		if (m_bIs64bit)
			iCalculateAddEsp *= 2;

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
		// the parameter type should also be PARAMETER_TYPE_POINTER
		if (m_CurrentInvokeInfo.params[0].ptype != PARAMETER_TYPE_POINTER)
		{
			#ifdef DEBUG_MESSAGES_ENABLED
			DebugShout("Warning: \"THIS\" parameter type invalid [%i], should be PARAMETER_TYPE_POINTER", m_CurrentInvokeInfo.params[0].ptype);
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

remote_thread_buffer_t CRemoteCode::AssembleRemoteThreadBuffer()
{
	if (m_bIs64bit)
	{
		// Restore Registers and return
		Epilogue64();
	}
	else
	{
		// Zero eax and return
		// xor eax, eax
		AddByteToBuffer(0x33);
		AddByteToBuffer(0xC0);
		// ret 4
		AddByteToBuffer(0xC2);
		AddByteToBuffer(0x04);
		AddByteToBuffer(0x00);
	}

	return GetRemoteThreadBuffer();
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

	unsigned char *newBuffer = new unsigned char[thread_data.size()];

	for (int i = 0; i < (int)thread_data.size(); i++)
	{
		newBuffer[i] = thread_data[i];
	}

	void *RemoteBuffer = CommitMemory(newBuffer, thread_data.size());

	delete[] newBuffer;

	if (RemoteBuffer == NULL)
		return false;

	HANDLE hThreadHandle = CreateRemoteThreadInProcess((LPTHREAD_START_ROUTINE)RemoteBuffer, NULL);
	if (hThreadHandle == INVALID_HANDLE_VALUE)
	{
		RemoteFreeMemory(RemoteBuffer, thread_data.size());
		DestroyRemoteThreadBuffer();

		#ifdef DEBUG_MESSAGES_ENABLED
		DebugShout("Failed to execute remote buffer in process 0x%X", m_hProcess);
		#endif

		return false;
	}

	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("Remote Buffer Executed in process 0x%X", m_hProcess);
	#endif

	if (async == true)
		WaitForSingleObject(hThreadHandle, INFINITE);

	RemoteFreeMemory(RemoteBuffer, thread_data.size());

	DestroyRemoteThreadBuffer();

	return true;
}

void CRemoteCode::DestroyRemoteThreadBuffer()
{
	for (size_t i = 0; i < m_CurrentInvokeInfo.strings.size(); i++)
	{
		RemoteFreeMemory(m_CurrentInvokeInfo.strings[i].ptr, m_CurrentInvokeInfo.strings[i].size);
	}

	m_CurrentInvokeInfo.calladdress = 0;
	m_CurrentInvokeInfo.params.clear();
	m_CurrentRemoteThreadBuffer.clear();
}

HANDLE CRemoteCode::CreateRemoteThreadInProcess(LPTHREAD_START_ROUTINE lpThread, LPVOID lpParam)
{
	return CreateRemoteThread(m_hProcess, NULL, NULL, lpThread, lpParam, NULL, NULL);
}

void CRemoteCode::Prologue64()
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

void CRemoteCode::Epilogue64()
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
	#ifdef DEBUG_MESSAGES_ENABLED
	DebugShout("Byte added to buffer: 0x%X", in);
	#endif
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
		//case PARAMETER_TYPE_POINTER:	// 
		case PARAMETER_TYPE_DOUBLE:		// all the same shit 8 bytes
		case PARAMETER_TYPE_INT64:		//
		{
			if (paraminfo->pparam)
			{
				unsigned __int64 ulParam = *(unsigned __int64 *)paraminfo->pparam;

				if (m_bIs64bit)
				{
					// mov rax, 0xACEACEACACEACEAC ; ulParam
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
				// if it is PARAMETER_TYPE_POINTER with a NULL pointer
				// we don't want to crash
				// push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(0x00);
			}
			break;
		}
		case PARAMETER_TYPE_POINTER:	//
		{
			if (paraminfo->pparam)
			{
				unsigned __int64 ulParam = *(unsigned __int64 *)paraminfo->pparam;

				if (m_bIs64bit)
				{
					// mov rax, 0xACEACEACACEACEAC ; ulParam
					// push rax
					AddByteToBuffer(0x48);
					AddByteToBuffer(0xB8);
					AddLong64ToBuffer(ulParam);
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
				// if it is PARAMETER_TYPE_POINTER with a NULL pointer
				// we don't want to crash
				// push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(0x00);
			}
			break;
		}
		case PARAMETER_TYPE_SHORT:		// all the same shit 4 bytes
		case PARAMETER_TYPE_INT:		//
		case PARAMETER_TYPE_FLOAT:		//
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
				// if it is PARAMETER_TYPE_POINTER with a NULL pointer
				// we don't want to crash
				// push 0
				AddByteToBuffer(0x68);
				AddLongToBuffer(NULL);
			}

			break;
		}
		case PARAMETER_TYPE_BYTE:
		{
			unsigned char ucParam = *(unsigned char*)paraminfo->pparam;

			// push ucParam
			AddByteToBuffer(0x6A); // 0x6A is for pushing bytes
			AddByteToBuffer(ucParam);

			break;
		}
		case PARAMETER_TYPE_BOOL:
		{
			bool bParam = *(bool*)paraminfo->pparam;

			unsigned char ucParam = (bParam) ? 1 : 0;

			// push ucParam
			AddByteToBuffer(0x6A);
			AddByteToBuffer(ucParam);

			break;
		}
		case PARAMETER_TYPE_STRING:
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
				// push rax
				AddByteToBuffer(0x48);
				AddByteToBuffer(0xB8);
				AddLong64ToBuffer((unsigned __int64)s.ptr);
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
		case PARAMETER_TYPE_WSTRING:
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
				// push rax
				AddByteToBuffer(0x48);
				AddByteToBuffer(0xB8);
				AddLong64ToBuffer((unsigned __int64)s.ptr);
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
	static const char *szCconvTypes[4] = {
		"CCONV_CDECL",
		"CCONV_STDCALL",
		"CCONV_THISCALL",
		"CCONV_FASTCALL"
	};
	return szCconvTypes[cconv];
}

string CRemoteCode::ParameterTypeToString(parameter_type_t type)
{
	static const char *szParameterTypes[] = {
		"PARAMETER_TYPE_INT",
		"PARAMETER_TYPE_INT64",
		"PARAMETER_TYPE_BOOL",
		"PARAMETER_TYPE_SHORT",
		"PARAMETER_TYPE_FLOAT",
		"PARAMETER_TYPE_DOUBLE",
		"PARAMETER_TYPE_BYTE",
		"PARAMETER_TYPE_POINTER",
		"PARAMETER_TYPE_STRING",
		"PARAMETER_TYPE_WSTRING"
	};
	return szParameterTypes[type];
}

#ifdef DEBUG_MESSAGES_ENABLED
void CRemoteCode::DebugShout(const char *fmt, ...)
{
	static bool doneOnce = false;
	if (!doneOnce)
	{
		char szAppDataPath[MAX_PATH];
		if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, NULL, szAppDataPath)))
		{
			for (int i = (int)strlen(szAppDataPath); i > 0; --i)
			{
				if (szAppDataPath[i] == '\\')
				{
					szAppDataPath[i + 1] = 0;
					break;
				}
			}
			strcpy_s(m_baseDir, szAppDataPath);
			strcat_s(m_baseDir, "Local\\injectora\\");
			Utils::CreateDirectoryIfNeeded(m_baseDir);
			printf_s("basedir: %s\n", m_baseDir);
		}
		else
		{
			printf_s("Unable to create log file!!\n");
		}

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
	m_logFile.open(m_infoLog);

	int count = 1;

	m_logFile << "RemoteThreadBuffer:" << std::endl << std::endl;

	m_logFile << std::endl << " offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F" 
			  << std::endl << "--------|------------------------------------------------\n00000000| ";

	OutputDebugString("\n offset | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n--------|------------------------------------------------\n00000000| ");

	std::string buf;
	for (size_t i = 0; i < m_CurrentRemoteThreadBuffer.size(); i++)
	{
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

	buf.append("\n\n");

	OutputDebugString(buf.c_str());

	m_logFile.close();
}
#endif
