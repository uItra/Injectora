#ifndef __MENU_COMPONENT_H__
#define __MENU_COMPONENT_H__

#include "JuceHeader.h"
#include "MainAppWindow.h"

class MenuComponent : public Component, public MenuBarModel
{
public:
	MenuComponent()
	{
		addAndMakeVisible(menuBar = new MenuBarComponent(this));
		setColour(PopupMenu::highlightedBackgroundColourId, Colours::darkred);
		setColour(PopupMenu::highlightedTextColourId, Colours::white);
	}

	~MenuComponent()
	{
		PopupMenu::dismissAllActiveMenus();
		menuBar = nullptr;
	}

	PopupMenu getMenuForIndex(int menuIndex, const String& /*menuName*/) override
	{
		
		ApplicationCommandManager* commandManager = MainAppWindow::getMainAppWindow()->getApplicationCommandManager();
		menu.clear();
		if (menuIndex == MainAppWindow::MenuFile)
		{
			menu.addCommandItem(commandManager, MainAppWindow::Open);
			menu.addSeparator();
			menu.addCommandItem(commandManager, MainAppWindow::Quit);
		}
		if (menuIndex == MainAppWindow::MenuOptions)
		{
			menu.addCommandItem(commandManager, MainAppWindow::ManualMap);
			menu.addCommandItem(commandManager, MainAppWindow::AutoInject);
			menu.addCommandItem(commandManager, MainAppWindow::CloseOnInject);
			menu.addSeparator();
			menu.addCommandItem(commandManager, MainAppWindow::NativeTitleBar);
		}
		if (menuIndex == MainAppWindow::MenuAbout)
		{
			menu.addCommandItem(commandManager, MainAppWindow::About);
		}

		return menu;
	}

	StringArray getMenuBarNames() override
	{
		const char* const names[] = { "File", "Options", "About", nullptr };
		return StringArray(names);
	}

	void menuItemSelected(int menuItemID, int /*topLevelMenuIndex*/) override
	{

	}

	void resized() override
	{
		juce::Rectangle<int> area(getLocalBounds());
		menuBar->setBounds(area.removeFromTop(20));
	}

private:
	PopupMenu menu;
	ScopedPointer<MenuBarComponent> menuBar;
};

#endif //__MENU_COMPONENT_H__