#include "ProcessesComponent.h"

ProcessesComponent::ProcessesComponent()
{
	LookAndFeel::setDefaultLookAndFeel(&lookAndFeelCustom);
    addAndMakeVisible(processList);
    processList.setName("process list");

    addAndMakeVisible(okButton = new TextButton("ok button"));
    okButton->setButtonText(TRANS("Okay"));
    okButton->addListener(this);

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

String ProcessesComponent::getCurrentProcess()
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

	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot Failed");
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("Process32First Failed");
		CloseHandle(hProcessSnap);
		return 0;
	}

	do 
	{
		if (strcmp("System", pe32.szExeFile) == 0 || strcmp("[System Process]", pe32.szExeFile) == 0)
			continue;
		ProcessInfo info;
		info.processId = pe32.th32ProcessID;
		info.processName = pe32.szExeFile;
		processes.add(info);
	} while (Process32Next(hProcessSnap, &pe32));

	processList.numRows = processes.size();
	processList.setProcessList(processes);
	processList.table.updateContent();

	CloseHandle(hProcessSnap);
	return 1;
}