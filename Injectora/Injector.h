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
	DWORD GetProcessIdByName(const char* process);
	void EnableDebugPriv();
	void SetProcessName(String name);
	void SetDLLName(String name);
	void SetManualMap(bool bManualMap);
	void SetAutoInject(bool bAutoInj);
	void SetCloseOnInject(bool bCloseOnInj);
	void timerCallback();
	void terminateTimer();
	bool isTimerAlive();
	void beginTimer();
	bool Setup();

	HRESULT ManualMap(String filePath);
	BOOL LoadLibraryInject(String filePath);


private:
	bool autoInject;
	bool closeOnInject;
	bool hasInjected;
	bool isManualMap;
	bool isReady;
	String DLL;
	Array<int> oldProcessIds;
	String processName;
	DWORD processId;
	HANDLE processHandle;
	CRemoteLoader remoteLoader;
};