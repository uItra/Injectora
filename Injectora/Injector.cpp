#include "Injector.h"

Injector::Injector() :
processName("default"),
autoInject(false),
closeOnInject(false),
hasInjected(false),
isManualMap(false),
isReady(false)
{
	hNtdll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	fnQSI = (tNTQSI)Utils::GetProcAddress(hNtdll, "NtQuerySystemInformation");
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

DWORD Injector::GetProcessId()
{
	ULONG cbBuffer = 131072;
	void* pBuffer = NULL;
	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	void* hHeap = GetProcessHeap();

	DWORD processId_ = 0;

	const char* process = processName.getCharPointer();
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

		Status = fnQSI(SystemProcessInformation, pBuffer, cbBuffer, &cbBuffer);
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
					processId_ = infoP->ProcessId;
					found = true;

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
	processId = GetProcessId();
	if (processId == 0)
	{
		MessageBox(0, "Could not find process!", "Injectora", MB_ICONEXCLAMATION);
		return false;
	}

	processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
	if (processHandle != NULL)
	{
		remoteLoader.SetProcess(processHandle, processId);
		return true;
	}

	MessageBox(0, "[Injector::Setup] Failed. Not able to open process handle!", "Injectora", MB_ICONERROR);

	return false;
}

void Injector::timerCallback()
{
	DWORD pidCheck = GetProcessId();		
	if (pidCheck != 0 && !canInject)
	{
		//if (pidCheck == processId)
		//{
			canInject = true;
			for (int i = 0; i < oldProcessIds.size(); i++)
			{
				if (oldProcessIds[i] == pidCheck)
				{
					//MessageBox(0, "Module already loaded into this process!", "Injectora", MB_ICONEXCLAMATION);
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
		//}
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

	File file(filePath);
	if (!file.exists())
	{
		MessageBox(0, "File selected to be injected does not exist!", "Injectora", MB_ICONERROR);
		isReady = false;
		return 2;
	}

	if (!Setup())
	{
		isReady = false;
		return 3;
	}

	HMODULE ret = remoteLoader.LoadLibraryByPathIntoMemoryA(filePath.toStdString().c_str(), false);
	if (!ret)
	{
		MessageBox(0, "Failed to Manual Map inject!", "Injectora", MB_ICONERROR);
		isReady = false;
		return 4;
	}

	// Beep of success
	MessageBeep(MB_OK);
	//if (!closeOnInject && !autoInject) {
	//	MessageBox(0, "Manual Map Success!", "Injectora", MB_ICONASTERISK);
	//}
	
	oldProcessIds.add(processId);

	CloseHandle(processHandle);
	
	isReady = false;

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
		return -1;
	}

	if (strlen(filePath.getCharPointer()) < 5)
	{
		MessageBox(0, "Select a DLL first!", "Injectora", MB_ICONEXCLAMATION);
		isReady = false;
		return 2;
	}

	File file(filePath);
	if (!file.exists())
	{
		MessageBox(0, "File selected to be injected does not exist!", "Injectora", MB_ICONERROR);
		isReady = false;
		return 2;
	}

	if (!Setup())
	{
		isReady = false;
		return 3;
	}

	int	bRet = FALSE;

	HMODULE returnedModule = remoteLoader.LoadLibraryByPathA(filePath.getCharPointer());
	if (returnedModule)
	{
		//MessageBox(0, "LoadLibrary injection success!", "Injectora", MB_ICONASTERISK);
		bRet = TRUE;
		oldProcessIds.add(processId);
	}
	else
	{
		MessageBox(0, "LoadLibraryByPathA Failed!", "Injectora", MB_ICONERROR);
		bRet = FALSE;
	}

	// Beep of success
	MessageBeep(MB_OK);

	// close process handle
	CloseHandle(processHandle);

	if (closeOnInject && bRet == TRUE)
		PostQuitMessage(0);

	return bRet;
}