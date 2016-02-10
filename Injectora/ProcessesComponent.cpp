#include "ProcessesComponent.h"

ProcessesComponent::ProcessesComponent()
{
	LookAndFeel::setDefaultLookAndFeel(&lookAndFeelCustom);
    addAndMakeVisible(processList);
    processList.setName("process list");

    addAndMakeVisible(okButton = new TextButton("ok button"));
    okButton->setButtonText(TRANS("Okay"));
    okButton->addListener(this);

	hNtdll = (HMODULE)Utils::GetLocalModuleHandle("ntdll.dll");
	fnQSI = (tNTQSI)Utils::GetProcAddress(hNtdll, "NtQuerySystemInformation");

	FetchProcessList();
	processList.loadData(false); 

	processList.table.getHeader().addColumn("Process", 1, 140, 18);
	processList.table.getHeader().addColumn("PID", 2, 50, 18);

	setSize(300, 350);
}

ProcessesComponent::~ProcessesComponent()
{
    okButton = nullptr;
}

ProcessInfo ProcessesComponent::getCurrentProcess()
{
	return processList.currentProcess;
}

TableComponent* ProcessesComponent::getProcessList()
{
	return &processList;
}

void ProcessesComponent::paint(Graphics& g)
{
    g.fillAll (Colour(0xffd1d1d1));
}

void ProcessesComponent::resized()
{
    processList.setBounds(8, 8, 284, 304);
	okButton->setBounds(72, 320, 152, 24);
}

void ProcessesComponent::buttonClicked(Button* buttonThatWasClicked)
{
    if (buttonThatWasClicked == okButton)
    {
		getPeer()->setVisible(false);
    }
}

bool ProcessesComponent::FetchProcessList()
{
	processes.clear();

	ULONG cbBuffer = 131072;
	void* pBuffer = NULL;
	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	void* hHeap = GetProcessHeap();

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
				if (pName && infoP->ProcessId)
				{
					if (_stricmp("System", pName) && _stricmp("[System Process]", pName))
					{
						ProcessInfo info;
						info.processId = infoP->ProcessId;
						info.processName = pName;

						processes.add(info);
					}
				}

				if (!infoP->NextEntryDelta)
					break;
				infoP = (PSYSTEM_PROCESSES)((unsigned char*)infoP + infoP->NextEntryDelta);
			}
			if (pBuffer)
				HeapFree(hHeap, NULL, pBuffer);
		}

		if (!check)
		{
			// Don't continuously search...
			break;
		}
	}

	processList.numRows = processes.size();
	processList.setProcessList(processes);
	processList.table.updateContent();

	return 1;
}