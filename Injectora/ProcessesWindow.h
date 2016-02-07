#ifndef __PROCESSES_WINDOW_H__
#define __PROCESSES_WINDOW_H__

#include "ProcessesComponent.h"

class ProcessesWindow : public DocumentWindow
{
public:
	ProcessesWindow();
	~ProcessesWindow();

	void closeButtonPressed();
	ProcessesComponent* getProcessComponent();

private:
	ScopedPointer<ProcessesComponent> processesComponent;
};

#endif // __PROCESSES_WINDOW_H__