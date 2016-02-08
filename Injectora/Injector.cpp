#include "Injector.h"

Injector::Injector() :
processName("default"),
autoInject(false),
closeOnInject(false),
hasInjected(false),
isManualMap(false),
isReady(false)
{
}

Injector::Injector(String nameIn) :
processName(nameIn),
autoInject(false),
closeOnInject(false),
hasInjected(false),
isManualMap(false),
isReady(false)
{
	Setup();
}

Injector::Injector(String nameIn, bool autoInjectIn, bool closeOnInjectIn) : 
processName(nameIn), 
autoInject(autoInjectIn), 
closeOnInject(closeOnInjectIn), 
hasInjected(false),
isManualMap(false),
isReady(false)
{
	Setup();
}

Injector::~Injector()
{
	if (isTimerRunning())
		stopTimer();
}

Injector::Injector(Injector& other)
{
	processName = other.processName;
	processId = other.processId;
	processHandle = other.processHandle;
	autoInject = other.autoInject;
	closeOnInject = other.closeOnInject;
	hasInjected = other.hasInjected;
	isManualMap = other.isManualMap;
	isReady = other.isReady;
	DLL = other.DLL;
}

DWORD Injector::GetProcessIdByName(const char* process)
{
	ULONG cbBuffer = 131072;
	void* pBuffer = NULL;
	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	void* hHeap = GetProcessHeap();

	DWORD processId_ = 0;

	HMODULE hNtdll = (HMODULE)Utils::getLocalModuleHandle("ntdll.dll");
	tNTQSI fpQSI = (tNTQSI)Utils::getProcAddress(hNtdll, "NtQuerySystemInformation");

	std::string name(process);
	if (!strstr(process, ".exe"))
		name += ".exe";

	bool check = false;
	bool found = false;
	while (!found)
	{
		pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cbBuffer);
		if (pBuffer == NULL)
			return 0;

		Status = fpQSI(SystemProcessInformation, pBuffer, cbBuffer, &cbBuffer);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			check = true;
			HeapFree(hHeap, NULL, pBuffer);
			cbBuffer *= 2;
		}
		else if (!NT_SUCCESS(Status))
		{
			HeapFree(hHeap, NULL, pBuffer);
			return 0;
		}
		else
		{
			check = false;

			PSYSTEM_PROCESSES infoP = (PSYSTEM_PROCESSES)pBuffer;
			while (infoP)
			{
				char pName[256];
				memset(pName, 0, sizeof(pName));
				WideCharToMultiByte(0, 0, infoP->ProcessName.Buffer, infoP->ProcessName.Length, pName, 256, NULL, NULL);

				if (_stricmp(name.c_str(), pName) == 0)
				{
					//printf("infoP: 0x%llp", infoP);
					processId_ = infoP->ProcessId;
					found = true;

					#ifdef _DEBUG
					printf("FOUND %S > processid: %i (0x%X)\n", infoP->ProcessName.Buffer, processId_, processId_);
					#endif

					break;
				}

				if (!infoP->NextEntryDelta)
					break;
				infoP = (PSYSTEM_PROCESSES)((unsigned char*)infoP + infoP->NextEntryDelta);
			}
			if (pBuffer)
				HeapFree(hHeap, NULL, pBuffer);
		}

		if (processId_ != 0)
		{
			break;
		}
		else if (!check)
		{
			// Don't continuously search...
			break;
		}
	}

	return processId_;
}

BOOL Injector::CheckValidProcessExtension(const char* name)
{
	if (!name)
		return false;
	unsigned int lenName = (unsigned int)strlen(name);
	unsigned int lenExt = (unsigned int)strlen(".exe");
	if (lenName >= lenExt)
		return !_stricmp(name + lenName - lenExt, ".exe");
	return false;
}

bool Injector::Setup()
{
	processId = GetProcessIdByName(processName.getCharPointer());
	#if defined _DEBUG
	printf("processId: 0x%X\n", processId);
	#endif
	if (!processId)
	{
		MessageBox(0, "Could not find process!\n", "Injectora", MB_ICONEXCLAMATION);
		return false;
	}

	processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
	#if defined _DEBUG
	printf("processHandle: 0x%X\n", processHandle);
	#endif
	if (processHandle != NULL)
	{
		remoteLoader.SetProcess(processHandle);

		return true;
	}

	MessageBox(0, "Injector[Setup] failure: not able to open process!", "Injectora", MB_ICONERROR);

	return false;
}

void Injector::SetProcessName(String name)
{
	processName = name;
}

void Injector::SetDLLName(String dllname)
{ 
	DLL = dllname;
}

void Injector::SetAutoInject(bool bAutoInj)
{
	autoInject = bAutoInj;
}

void Injector::SetManualMap(bool bManualMap)
{
	isManualMap = bManualMap;
}

void Injector::SetCloseOnInject(bool bCloseOnInj)
{
	//printf("closeOnInject: %s\n", closeOnInject ? "true" : "false");
	closeOnInject = bCloseOnInj;
}

void Injector::terminateTimer()
{
	stopTimer();
}

bool Injector::isTimerAlive()
{
	return isTimerRunning();
}

void Injector::beginTimer()
{
	startTimer(750);
}

void Injector::timerCallback()
{
	//printf_s("Checking for %s\n", processName.getCharPointer());

	ULONG cbBuffer = 131072;
	void* pBuffer = NULL;
	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	void* hHeap = GetProcessHeap();

	DWORD processId_ = 0;

	HMODULE hNtdll = (HMODULE)Utils::getLocalModuleHandle("ntdll.dll");
	tNTQSI fpQSI = (tNTQSI)Utils::getProcAddress(hNtdll, "NtQuerySystemInformation");

	bool found = false;
	while (!found)
	{
		pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cbBuffer);
		if (pBuffer == NULL)
			return;

		Status = fpQSI(SystemProcessInformation, pBuffer, cbBuffer, &cbBuffer);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			HeapFree(hHeap, NULL, pBuffer);
			cbBuffer *= 2;
		}
		else if (!NT_SUCCESS(Status))
		{
			HeapFree(hHeap, NULL, pBuffer);
			return;
		}
		else
		{
			PSYSTEM_PROCESSES infoP = (PSYSTEM_PROCESSES)pBuffer;
			while (infoP)
			{
				//char pName[256];
				//memset(pName, 0, sizeof(pName));
				//WideCharToMultiByte(0, 0, infoP->ProcessName.Buffer, infoP->ProcessName.Length, pName, 256, NULL, NULL);
				if (_wcsnicmp(infoP->ProcessName.Buffer, processName.toWideCharPointer(), infoP->ProcessName.Length) == 0)
				{
					processId_ = infoP->ProcessId;
					found = true;

					#ifdef _DEBUG
					printf("FOUND %S > processid: %i (0x%X)\n", infoP->ProcessName.Buffer, processId_, processId_);
					#endif

					bool canInject = true;
					for (int i = 0; i < oldProcessIds.size(); i++)
					{
						if (oldProcessIds[i] == processId_)
						{
							MessageBox(0, "Module already loaded into this process!", "Injectora", MB_ICONEXCLAMATION);
							canInject = false;
							break;
						}
					}

					if (canInject)
					{
						isReady = true;
						if (isManualMap)
							ManualMap(DLL);
						else
							LoadLibraryInject(DLL);
					}

					break;
				}

				if (!infoP->NextEntryDelta)
					break;
				infoP = (PSYSTEM_PROCESSES)((unsigned char*)infoP + infoP->NextEntryDelta);
			}
			if (pBuffer)
				HeapFree(hHeap, NULL, pBuffer);
		}

		if (processId_ != 0)
		{
			break;
		}
		else
		{
			// Don't continuously search...
			break;
		}
	}
}

HRESULT Injector::ManualMap(String filePath)
{
	DLL = filePath;

	if (!autoInject)
		isReady = true;

	if (!isReady)
		return 0;

	if (!CheckValidProcessExtension(processName.getCharPointer()))
	{
		printf("Invalid Process Name!\n");
		isReady = false;
		return 1;
	}

	if (strlen(filePath.getCharPointer()) < 5)
	{
		printf("Select a DLL first!\n");
		isReady = false;
		return 2;
	}

	if (!Setup())
	{
		isReady = false;
		return 3;
	}

	printf("Manual Mapping.....\n");
	HMODULE ret = remoteLoader.LoadLibraryByPathIntoMemoryA(filePath.toStdString().c_str(), false);
	if (!ret)
	{
		printf("Failed to inject!");
		isReady = false;
		return 4;
	}

	if (!closeOnInject && !autoInject)
		MessageBox(0, "Manual Map Success!", "Injectora", MB_ICONASTERISK);
	
	oldProcessIds.add(processId);
	
	isReady = false;

	//printf("closeOnInject: %s\n", closeOnInject ? "ture" : "false");
	if (closeOnInject)
		PostQuitMessage(0);
	
	return 0;
}

BOOL Injector::LoadLibraryInject(String filePath)
{
	isManualMap = false;
	DLL = filePath;

	if (!autoInject)
		isReady = true;

	if (!isReady)
		return 0;

	if (!CheckValidProcessExtension(processName.getCharPointer()))
	{
		MessageBox(0, "Invalid Process Name!", "Injectora", MB_ICONEXCLAMATION);
		isReady = false;
		return 1;
	}

	if (strlen(filePath.getCharPointer()) < 5)
	{
		printf("Select a DLL first!\n");
		isReady = false;
		return 2;
	}
	
	if (!Setup())
	{
		isReady = false;
		return 3;
	}

	DWORD	dwMemSize;
	LPVOID	lpRemoteMem, lpLoadLibrary;
	int	bRet = FALSE;
	
	printf("Normal LoadLibrary Injection\n");

	dwMemSize = filePath.length() + 1;
	lpRemoteMem = VirtualAllocEx(processHandle, NULL, dwMemSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpRemoteMem != NULL)
	{
		if (WriteProcessMemory(processHandle, lpRemoteMem, (LPCVOID)filePath.getCharPointer(), dwMemSize, NULL))
		{
			lpLoadLibrary = remoteLoader.GetRemoteProcAddress("Kernel32.dll", "LoadLibraryA");
			if (CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibrary, lpRemoteMem, 0, NULL) != NULL)
			{
				printf("LoadLibrary Injection Successful!!\n");
				oldProcessIds.add(processId);

				bRet = 0;
			}
			else
			{
				printf("Could not create remote thread\n");
				bRet = 6;
			}
		}
		else
		{
			printf("WriteProcessMemory failed\n");
			bRet = 5;
		}
	}
	else
	{
		printf("Couldn't allocate memory!\n");
		bRet = 4;
	}

	CloseHandle(processHandle);

	if (bRet == TRUE && closeOnInject)
		PostQuitMessage(0);

	return bRet;
}