#pragma once

#include "JuceHeader.h"
#include "CRemoteLoader.h"

class Injector : private Timer
{
public:
	Injector();
	Injector(String nameIn);
	Injector(String nameIn, bool autoInjectIn, bool closeOnInjectIn);

	~Injector();

	Injector(Injector& other);

	BOOL CheckValidProcessExtension(const char* name);
	DWORD GetProcessId();
	void EnableDebugPriv() { Utils::SetDebugPrivilege(TRUE); };

	void SetProcessInformation(ProcessInfo processInfo) 
	{ 
		processName = processInfo.processName; 
		processId = processInfo.processId; 
	}

	void SetDLLName(String dllname) { DLL = dllname; }
	void SetAutoInject(bool bAutoInj) { autoInject = bAutoInj; }
	void SetManualMap(bool bManualMap) { isManualMap = bManualMap; }
	void SetCloseOnInject(bool bCloseOnInj) { closeOnInject = bCloseOnInj; }

	void timerCallback();
	void beginTimer() { startTimer(750); }
	void terminateTimer() { stopTimer(); }
	bool isTimerAlive() { return isTimerRunning(); }

	bool Setup();

	HRESULT ManualMap(String filePath);
	BOOL LoadLibraryInject(String filePath);

private:
	bool autoInject;
	bool closeOnInject;
	bool hasInjected;
	bool isManualMap;
	bool isReady;
	bool canInject;
	String DLL;
	Array<int> oldProcessIds;
	String processName;
	DWORD processId;
	HANDLE processHandle;
	CRemoteLoader remoteLoader;

	HMODULE hNtdll;
	tNTQSI fnQSI;
};