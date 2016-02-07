#include "ProcessesWindow.h"

ProcessesWindow::ProcessesWindow() : DocumentWindow("Processes", Colours::white, DocumentWindow::closeButton)
{
	processesComponent = new ProcessesComponent();
	setResizable(false, false);
	setContentOwned(processesComponent, true);
	centreWithSize(getWidth(), getHeight());
	setVisible(false);
}

ProcessesWindow::~ProcessesWindow()
{
	processesComponent = nullptr;
}

void ProcessesWindow::closeButtonPressed()
{
	setVisible(false);
}

ProcessesComponent* ProcessesWindow::getProcessComponent()
{
	return processesComponent;
}