#ifndef __PROCESSES_COMPONENT_H__
#define __PROCESSES_COMPONENT_H__

#include "JuceHeader.h"
#include "TableComponent.h"
#include "LookAndFeelCustom.h"

class ProcessesComponent : public Component, public ButtonListener
{
public:

	ProcessesComponent();
	~ProcessesComponent();

    void paint(Graphics& g);
    void resized();
    void buttonClicked(Button* buttonThatWasClicked);
	bool FetchProcessList();
	String getCurrentProcess();
	TableComponent* getProcessList();

private:
    TableComponent processList;

    ScopedPointer<TextButton> okButton;

	LookAndFeelCustom lookAndFeelCustom;
	
	Array<ProcessInfo> processes;

	JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(ProcessesComponent)
};


#endif   // __PROCESSES_COMPONENT_H__
