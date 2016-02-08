#include "MainComponent.h"
#include "MenuComponent.h"

ScopedPointer<TextEditor>		processEditor;
ScopedPointer<Component>		dllComponent;

MainComponent::MainComponent() : manualMap(false), autoInject(false), closeOnInject(false)
{
	processesWindow = new ProcessesWindow();
	aboutWindow = new AboutWindow();

	injector.EnableDebugPriv();

	injector.SetManualMap(manualMap);
	injector.SetAutoInject(autoInject);
	injector.SetCloseOnInject(closeOnInject);

	LookAndFeel::setDefaultLookAndFeel(&lookAndFeelCustom);
	addAndMakeVisible(menuComponent = new MenuComponent());

    addAndMakeVisible(processesButton = new TextButton("processes button"));
    processesButton->setButtonText(TRANS("Select"));
    processesButton->setConnectedEdges(Button::ConnectedOnLeft | Button::ConnectedOnRight | Button::ConnectedOnTop | Button::ConnectedOnBottom);
    processesButton->addListener(this);
    processesButton->setColour(TextButton::buttonColourId, Colour(0xff700000));
	processesButton->setColour(TextButton::buttonOnColourId, Colour(0xff700000));
    processesButton->setColour(TextButton::textColourOnId, Colours::white);
    processesButton->setColour(TextButton::textColourOffId, Colours::white);

	addChildComponent(dllComponent = new Component("DLL"));
	dllComponent->addComponentListener(this);

    addAndMakeVisible(processEditor = new TextEditor("process editor"));
	processEditor->setTooltip(TRANS("Process to be injected"));
	processEditor->setMultiLine(false);
	processEditor->setReturnKeyStartsNewLine(false);
	processEditor->setReadOnly(false);
	processEditor->setScrollbarsShown(true);
    processEditor->setCaretVisible(true);
    processEditor->setPopupMenuEnabled(true);
	processEditor->setColour(TextEditor::focusedOutlineColourId, Colours::blueviolet);
	processEditor->setColour(TextEditor::outlineColourId, Colour(0xff700000));
	processEditor->setColour(TextEditor::textColourId, Colour(0xff700000));
	processEditor->setFont(Font("Tahoma", 15.0f, Font::plain));
	processEditor->addListener(this);
	
    addAndMakeVisible(processLabel = new Label("process label", TRANS("Process:")));
    processLabel->setFont(Font(15.00f, Font::plain));
    processLabel->setJustificationType(Justification::centredLeft);
    processLabel->setEditable(false, false, false);
    processLabel->setColour(Label::textColourId, Colours::white);
    processLabel->setColour(TextEditor::textColourId, Colours::black);
    processLabel->setColour(TextEditor::backgroundColourId, Colour(0x00000000));

    addAndMakeVisible(injectButton = new TextButton("inject button"));
    injectButton->setButtonText(TRANS("Inject"));
    injectButton->setConnectedEdges(Button::ConnectedOnLeft | Button::ConnectedOnRight | Button::ConnectedOnTop | Button::ConnectedOnBottom);
    injectButton->addListener(this);
    injectButton->setColour(TextButton::buttonColourId, Colour(0xff700000));
    injectButton->setColour(TextButton::buttonOnColourId, Colour(0xff700000));
    injectButton->setColour(TextButton::textColourOnId, Colours::white);
    injectButton->setColour(TextButton::textColourOffId, Colours::white);

    addAndMakeVisible(groupComponent = new GroupComponent("new group", TRANS("DLL")));
    groupComponent->setTextLabelPosition(Justification::centredLeft);
    groupComponent->setColour(GroupComponent::outlineColourId, Colours::white);
    groupComponent->setColour(GroupComponent::textColourId, Colours::white);

    addAndMakeVisible(openButton = new TextButton("open button"));
    openButton->setTooltip(TRANS("Select the dll to inject"));
    openButton->setButtonText(TRANS("Select DLL"));
    openButton->setConnectedEdges(Button::ConnectedOnLeft | Button::ConnectedOnRight | Button::ConnectedOnTop | Button::ConnectedOnBottom);
    openButton->addListener(this);
    openButton->setColour(TextButton::buttonColourId, Colour(0xff700000));
    openButton->setColour(TextButton::buttonOnColourId, Colour(0xff700000));
    openButton->setColour(TextButton::textColourOnId, Colours::white);
    openButton->setColour(TextButton::textColourOffId, Colours::white);

    addAndMakeVisible(removeButton = new TextButton("remove button"));
    removeButton->setTooltip(TRANS("Remove selected dll"));
    removeButton->setButtonText(TRANS("Remove"));
    removeButton->setConnectedEdges(Button::ConnectedOnLeft | Button::ConnectedOnRight | Button::ConnectedOnTop | Button::ConnectedOnBottom);
    removeButton->addListener(this);
    removeButton->setColour(TextButton::buttonColourId, Colour(0xff700000));
    removeButton->setColour(TextButton::buttonOnColourId, Colour(0xff700000));
    removeButton->setColour(TextButton::textColourOnId, Colours::white);
    removeButton->setColour(TextButton::textColourOffId, Colours::white);

    addAndMakeVisible(clearButton = new TextButton("clear button"));
    clearButton->setTooltip(TRANS("clear all dlls"));
    clearButton->setButtonText(TRANS("Clear"));
    clearButton->setConnectedEdges(Button::ConnectedOnLeft | Button::ConnectedOnRight | Button::ConnectedOnTop | Button::ConnectedOnBottom);
    clearButton->addListener(this);
    clearButton->setColour(TextButton::buttonColourId, Colour(0xff700000));
    clearButton->setColour(TextButton::buttonOnColourId, Colour(0xff700000));
    clearButton->setColour(TextButton::textColourOnId, Colours::white);
    clearButton->setColour(TextButton::textColourOffId, Colours::white);

    addAndMakeVisible(aboutButton = new TextButton("about button"));
    aboutButton->setButtonText(TRANS("About"));
    aboutButton->setConnectedEdges(Button::ConnectedOnLeft | Button::ConnectedOnRight | Button::ConnectedOnTop | Button::ConnectedOnBottom);
    aboutButton->addListener(this);
    aboutButton->setColour(TextButton::buttonColourId, Colour(0xff700000));
    aboutButton->setColour(TextButton::buttonOnColourId, Colour(0xff700000));
    aboutButton->setColour(TextButton::textColourOnId, Colours::white);
    aboutButton->setColour(TextButton::textColourOffId, Colours::white);

	addAndMakeVisible(tableList = new TableComponent());
	tableList->loadData(true);
	
	loadSettings();

	tableList->setBounds(112, 70, 222, 90);
	forEachXmlChildElement(*tableList->columnList, columnXml)
	{
		tableList->table.getHeader().addColumn(columnXml->getStringAttribute("name"), columnXml->getIntAttribute("columnId"),
									columnXml->getIntAttribute("width"), 15, 25, 400, TableHeaderComponent::defaultFlags);
	}

	processEditor->setText(process);

    setSize(350, 200);
}

MainComponent::~MainComponent()
{
	dllComponent = nullptr;
	processEditor = nullptr;

	processesButton = nullptr;
	processLabel = nullptr;
	injectButton = nullptr;
	groupComponent = nullptr;
	openButton = nullptr;
	removeButton = nullptr;
	clearButton = nullptr;
	aboutButton = nullptr;
	tableList = nullptr;
	menuComponent = nullptr;

	delete settingsData;
}

String MainComponent::openFile()
{
	TCHAR szDir[MAX_PATH];
	GetModuleFileName(NULL, szDir, MAX_PATH);
	String myDir = szDir;
	myDir = myDir.upToLastOccurrenceOf(".", false, true);
	File file(myDir + "_settings.xml");
	if (file.exists())
		return file.loadFileAsString();
	return String::empty;
}

void MainComponent::loadSettings()
{
	String data = openFile();
	if (data != String::empty)
	{
		XmlDocument dataDoc(data);
		settingsData = dataDoc.getDocumentElement();
	}
	else
	{
		XmlDocument dataDoc(String((const char*)BinaryData::table_data_xml));
		settingsData = dataDoc.getDocumentElement();
	}

	settingsList = settingsData->getChildByName("SETTINGS");
	settings = settingsList->getChildByName("SETTING");

	manualMap = settings->getBoolAttribute("manualMap");
	autoInject = settings->getBoolAttribute("autoInject");
	closeOnInject = settings->getBoolAttribute("closeOnInject");
	process = settings->getStringAttribute("process");

	MainAppWindow* maw;
	do 
	{
		maw = MainAppWindow::getMainAppWindow();
		if (maw)
			maw->setUsingNativeTitleBar(settings->getBoolAttribute("nativeWindow"));
	} while (!maw);
	
}

void MainComponent::saveSettings()
{
	settings->setAttribute("manualMap", manualMap ? "true" : "false");
	settings->setAttribute("autoInject", autoInject ? "true" : "false");
	settings->setAttribute("closeOnInject", closeOnInject ? "true" : "false");
	settings->setAttribute("nativeWindow", MainAppWindow::getMainAppWindow()->isUsingNativeTitleBar() ? "true" : "false");
	settings->setAttribute("process", processEditor->getText());
	
	char szDir[MAX_PATH];
	GetModuleFileName(NULL, szDir, MAX_PATH);
	String myDir = szDir;
	myDir = myDir.upToLastOccurrenceOf(".", false, true);
	File file(myDir + "_settings.xml");

	XmlElement* dllData = new XmlElement("DATA");
	forEachXmlChildElement(*tableList->dataList, itemXml)
	{
		XmlElement* tempElementItem = new XmlElement("ITEM");
		tempElementItem->setAttribute("DLL", itemXml->getStringAttribute("DLL"));
		tempElementItem->setAttribute("Size", itemXml->getStringAttribute("Size"));
		tempElementItem->setAttribute("Path", itemXml->getStringAttribute("Path"));
		dllData->addChildElement(tempElementItem);
	}

	settingsData->removeChildElement(settingsData->getChildByName("DATA"), true);
	settingsData->insertChildElement(dllData, -1);

	settingsData->writeToFile(file, "<!-- :: AUTO-GENERATED BY INJECTORA :: EDIT AT YOUR OWN RISK. -->");
}

void MainComponent::paint(Graphics& g)
{
	g.fillAll(Colour(0xffb10000));
}

void MainComponent::resized()
{
	juce::Rectangle<int> area(getLocalBounds());
	menuComponent->setBounds(area.removeFromTop(LookAndFeel::getDefaultLookAndFeel().getDefaultMenuBarHeight()));
	processesButton->setBounds(proportionOfWidth(0.8457f), proportionOfHeight(0.1500f), proportionOfWidth(0.1314f), proportionOfHeight(0.1200f));
	processEditor->setBounds(proportionOfWidth(0.2000f), proportionOfHeight(0.1500f), proportionOfWidth(0.6114f), proportionOfHeight(0.1200f));
	processLabel->setBounds(proportionOfWidth(0.0229f), proportionOfHeight(0.1500f), proportionOfWidth(0.1829f), proportionOfHeight(0.1200f));
    injectButton->setBounds(proportionOfWidth(0.5686f), proportionOfHeight(0.8300f), proportionOfWidth(0.3086f), proportionOfHeight(0.1200f));
    groupComponent->setBounds(proportionOfWidth(0.3200f), proportionOfHeight(0.3000f), proportionOfWidth(0.6343f), proportionOfHeight(0.5000f));
    openButton->setBounds(proportionOfWidth(0.0400f), proportionOfHeight(0.3400f), proportionOfWidth(0.2514f), proportionOfHeight(0.1200f));
    removeButton->setBounds(proportionOfWidth(0.0400f), proportionOfHeight(0.4950f), proportionOfWidth(0.2514f), proportionOfHeight(0.1200f));
    clearButton->setBounds(proportionOfWidth(0.0400f), proportionOfHeight(0.6500f), proportionOfWidth(0.2514f), proportionOfHeight(0.1200f));
    aboutButton->setBounds(proportionOfWidth(0.1171f), proportionOfHeight(0.8300f), proportionOfWidth(0.3086f), proportionOfHeight(0.1200f));
	tableList->setBounds(proportionOfWidth(0.3200f), proportionOfHeight(0.3400f), proportionOfWidth(0.6343f), proportionOfHeight(0.4600f));
}

void MainComponent::buttonClicked(Button* buttonThatWasClicked)
{
    if (buttonThatWasClicked == processesButton)
    {
		MainAppWindow* mainWindow = MainAppWindow::getMainAppWindow();
		if (mainWindow == nullptr)
			return;
		processesWindow->setUsingNativeTitleBar(mainWindow->isUsingNativeTitleBar());
		processesWindow->getProcessComponent()->FetchProcessList();
		processesWindow->setVisible(true);
    }
    else if (buttonThatWasClicked == injectButton)
    {
		//printf("Process: %s\tDLL: %s\n", processEditor->getText(), tableList->currentDll);
		if (tableList->currentDll.length() < 2)
		{
			MessageBox(0, "Select a DLL!", "Injectora", MB_ICONEXCLAMATION);
			return;
		}

		injector.SetProcessName(processEditor->getText());
		injector.SetAutoInject(autoInject);
		injector.SetCloseOnInject(closeOnInject);
		injector.SetManualMap(manualMap);

		if (manualMap)
			injector.ManualMap(tableList->currentDll);
		else
			injector.LoadLibraryInject(tableList->currentDll);
    }
    else if (buttonThatWasClicked == openButton)
    {
		FileChooser fc("Choose a file to open...", File::getCurrentWorkingDirectory(), "*.*", true);
		if (fc.browseForFileToOpen())
		{
			dllDirectory = fc.getResult();
			dllName = dllDirectory.getFileName();
			
			XmlElement* newElement = new XmlElement("ITEM");
			//printf("DLL=%s Size=%i Path=%s\n", dllName, dllDirectory.getSize(), dllDirectory.getFullPathName());
			newElement->setAttribute("DLL", dllName);
			newElement->setAttribute("Size", (int)dllDirectory.getSize());
			newElement->setAttribute("Path", dllDirectory.getFullPathName());

			tableList->dataList->addChildElement(newElement);
			tableList->numRows++;
			tableList->table.updateContent();

			saveSettings();
		}
    }
    else if (buttonThatWasClicked == removeButton)
    {
		if (tableList->numRows > 0)
		{
			tableList->dataList->removeChildElement(tableList->dataList->getChildElement(tableList->table.getSelectedRow()), true);
			tableList->numRows--;
			tableList->table.updateContent();
			saveSettings();
		}
    }
    else if (buttonThatWasClicked == clearButton)
    {
		if (tableList->numRows > 0)
		{
			for (int i = tableList->dataList->getNumChildElements(); i >= 0; i--)
			{
				tableList->dataList->removeChildElement(tableList->dataList->getChildElement(i), true);
			}
			tableList->numRows = 0;
			tableList->table.updateContent();
			saveSettings();
		}
    }
    else if (buttonThatWasClicked == aboutButton)
    {
		MainAppWindow* mainWindow = MainAppWindow::getMainAppWindow();
		if (mainWindow == nullptr)
			return;
		aboutWindow->setUsingNativeTitleBar(mainWindow->isUsingNativeTitleBar());
		aboutWindow->setVisible(true);
    }
}

void MainComponent::textEditorTextChanged(TextEditor& editorThatChanged)
{
	if (&editorThatChanged == processEditor)
	{
		saveSettings();
		injector.SetProcessName(processEditor->getText());
	}
}

void MainComponent::componentNameChanged(Component& componentThatChanged)
{
	if (&componentThatChanged == dllComponent)
	{
		saveSettings();
		injector.SetDLLName(tableList->currentDll);
	}
}

ApplicationCommandTarget* MainComponent::getNextCommandTarget()
{
	// this will return the next parent component that is an ApplicationCommandTarget 
	// (in this case, there probably isn't one, but it's best to use this method in your own apps).
	return findFirstTargetParentComponent();
}

void MainComponent::getAllCommands(Array<CommandID>& commands)
{
	// this returns the set of all commands that this target can perform..
	const CommandID ids[] = 
	{ 
		MainAppWindow::Quit,
		MainAppWindow::Open,
		MainAppWindow::ManualMap,
		MainAppWindow::AutoInject,
		MainAppWindow::CloseOnInject,
		MainAppWindow::NativeTitleBar,
		MainAppWindow::About
	};
	commands.addArray(ids, numElementsInArray(ids));
}

void MainComponent::getCommandInfo(CommandID commandID, ApplicationCommandInfo& result)
{
	const String fileCategory("File");
	const String optionsCategory("Options");
	const String aboutCategory("About");
	switch (commandID)
	{
	case MainAppWindow::Quit:
		result.setInfo("Quit", "Quits the program", fileCategory, 0);
		result.addDefaultKeypress('Q', ModifierKeys::commandModifier);
		break;
	case MainAppWindow::Open:
		result.setInfo("Open", "Opens file dialog for choosing a dll", fileCategory, 0);
		result.addDefaultKeypress('O', ModifierKeys::commandModifier);
		break;
	case MainAppWindow::ManualMap:
		result.setInfo("Manual Map", "Sets manual mapping injection on or off", optionsCategory, 0);
		result.setTicked(manualMap);
		injector.SetManualMap(manualMap);
		break;
	case MainAppWindow::AutoInject:
		result.setInfo("Auto Inject", "Sets auto injection on or off", optionsCategory, 0);
		result.setTicked(autoInject);

		injector.SetAutoInject(autoInject);
		if (autoInject)
			injector.beginTimer();
		else
		{
			if (injector.isTimerAlive())
				injector.terminateTimer();
		}
		break;
	case MainAppWindow::CloseOnInject:
		result.setInfo("Close On Inject", "Closes Injectora upon successful injection", optionsCategory, 0);
		result.setTicked(closeOnInject);
		injector.SetCloseOnInject(closeOnInject);
		break;
	case MainAppWindow::NativeTitleBar:
	{
		result.setInfo("Native Title Bar", "Changes title bar theme", optionsCategory, 0);
		result.addDefaultKeypress('N', ModifierKeys::commandModifier);
		bool nativeTitlebar = false;
		if (MainAppWindow* map = MainAppWindow::getMainAppWindow())
			nativeTitlebar = map->isUsingNativeTitleBar();
		result.setTicked(nativeTitlebar);
		break;
	}
	case MainAppWindow::About:
	{
		result.setInfo("About", "Shows the about info", aboutCategory, 0);
		break;
	}
	default:
		break;
	}
}

bool MainComponent::perform(const InvocationInfo& info)
{
	MainAppWindow* mainWindow = MainAppWindow::getMainAppWindow();
	if (mainWindow == nullptr)
		return true;

	switch (info.commandID)
	{
	case MainAppWindow::Quit: 
		JUCEApplication::getInstance()->systemRequestedQuit(); 
		break;
	case MainAppWindow::Open:
		buttonClicked(openButton);
		break;
	case MainAppWindow::ManualMap:
		manualMap = !manualMap;
		break;
	case MainAppWindow::AutoInject:
	{	
		autoInject = !autoInject;
		if (autoInject)
		{
			injector.SetProcessName(processEditor->getText());
			injector.SetAutoInject(autoInject);
			injector.SetCloseOnInject(closeOnInject);
			injector.SetManualMap(manualMap);
			injector.beginTimer();
		}
		else
		{
			if (injector.isTimerAlive())
				injector.terminateTimer();
		}
		break;
	}
	case MainAppWindow::CloseOnInject:
		closeOnInject = !closeOnInject;
		//printf("closeOnInject: %s\n", closeOnInject ? "true" : "false");
		break;
	case MainAppWindow::NativeTitleBar:
		mainWindow->setUsingNativeTitleBar(!mainWindow->isUsingNativeTitleBar());
		break;
	case MainAppWindow::About:
		aboutWindow->setUsingNativeTitleBar(mainWindow->isUsingNativeTitleBar());
		aboutWindow->setVisible(true);
		break;
	default:
		return false;
	}
	
	saveSettings();
	
	return true;
}
