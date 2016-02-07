#ifndef __MAIN_APP_WINDOW_H__
#define __MAIN_APP_WINDOW_H__

#include "JuceHeader.h"
#include "MainComponent.h"

class MainAppWindow : public DocumentWindow, private AsyncUpdater
{
public:
	MainAppWindow();
	~MainAppWindow();

	void closeButtonPressed();
	void handleAsyncUpdate();

	ApplicationCommandManager* getApplicationCommandManager()
	{
		if (applicationCommandManager == nullptr)
			applicationCommandManager = new ApplicationCommandManager();
		return applicationCommandManager;
	}

	static MainAppWindow* getMainAppWindow()
	{
		for (int i = TopLevelWindow::getNumTopLevelWindows(); --i >= 0;)
			if (MainAppWindow* maw = dynamic_cast<MainAppWindow*>(TopLevelWindow::getTopLevelWindow(i)))
				return maw;
		return nullptr;
	}

	static MainComponent* getMainComponent()
	{
		MainAppWindow* main = getMainAppWindow();
		if (main)
			return main->mainComponent;
		return nullptr;
	}

	enum CommandIDs
	{
		Quit = 0x2000,
		Open = 0x2001,
		ManualMap = 0x2002,
		AutoInject = 0x2003,
		CloseOnInject = 0x2004,
		NativeTitleBar = 0x2005,
		About = 0x2006
	};

	enum MenuIndexes
	{
		MenuFile = 0,
		MenuOptions,
		MenuAbout
	};

private:
	ScopedPointer<ApplicationCommandManager> applicationCommandManager;
	ScopedPointer<MainComponent>	mainComponent;
};

#endif // __MAIN_APP_WINDOW_H__
