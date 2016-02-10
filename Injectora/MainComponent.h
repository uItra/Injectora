#ifndef __MAIN_COMPONENT_H__
#define __MAIN_COMPONENT_H__

#include "JuceHeader.h"
#include "ProcessesWindow.h"
#include "AboutWindow.h"
#include "LookAndFeelCustom.h"
#include "Injector.h"

class AboutWindow;
class ProcessesWindow;
class MenuComponent;
class TableComponent;
class ProcessesComponent;

class MainComponent : public Component, public ComponentListener, public ButtonListener, public TextEditorListener, public ApplicationCommandTarget
{
public:
	MainComponent();
	~MainComponent();

	String openFile();
	void loadSettings();
	void saveSettings();

	void paint(Graphics& g) override;
	void resized() override;
	void buttonClicked(Button* buttonThatWasClicked) override;
	void textEditorTextChanged(TextEditor& editor) override;
	void componentNameChanged(Component& component) override;

	ApplicationCommandTarget* getNextCommandTarget() override;
	void getAllCommands(Array<CommandID>& commands) override;
	void getCommandInfo(CommandID commandID, ApplicationCommandInfo& result) override;
	bool perform(const InvocationInfo& info) override;


private:
	ScopedPointer<TextButton>		processesButton;
	ScopedPointer<Label>			processLabel;
	ScopedPointer<TextButton>		injectButton;
	ScopedPointer<GroupComponent>	groupComponent;
	ScopedPointer<TextButton>		openButton;
	ScopedPointer<TextButton>		removeButton;
	ScopedPointer<TextButton>		clearButton;
	ScopedPointer<TextButton>		aboutButton;
	ScopedPointer<TableComponent>	tableList;
	ScopedPointer<MenuComponent>	menuComponent;

	ScopedPointer<ProcessesWindow>	processesWindow;
	ScopedPointer<AboutWindow>		aboutWindow;

	LookAndFeelCustom				lookAndFeelCustom;
	
	XmlElement*						settingsData;
	XmlElement*						settingsList;
	XmlElement*						settings;
	bool							settingsHaveBeenLoaded;

	bool							manualMap;
	bool							autoInject;
	bool							closeOnInject;

	File							dllDirectory;
	String							dllName;

	ProcessInfo						process;

	Injector						injector;

	JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(MainComponent)
};


#endif   // __MAIN_COMPONENT_H__
