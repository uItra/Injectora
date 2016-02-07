#include "JuceLibraryCode/JuceHeader.h"
#include "MainAppWindow.h"

#ifdef DEBUG_MESSAGES_ENABLED
__inline void CreateDebugConsole(const char* lPConsoleTitle)
{
	HANDLE lStdHandle = 0;
	int hConHandle = 0;
	FILE *fp = 0;
	AllocConsole();
	lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
	SetConsoleTitle(lPConsoleTitle);
	SetConsoleTextAttribute(lStdHandle, FOREGROUND_RED | FOREGROUND_BLUE | BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE);
	fp = _fdopen(hConHandle, "w");
	*stdout = *fp;
	setvbuf(stdout, NULL, _IONBF, 0);
}
#endif

class InjectoraApplication : public JUCEApplication
{
public:
	InjectoraApplication() { 
		#ifdef DEBUG_MESSAGES_ENABLED
		CreateDebugConsole("Debug"); 
		#endif
	}

	~InjectoraApplication() {
		mainWindow = nullptr;
	}

    const String getApplicationName() override			{ return ProjectInfo::projectName; }
    const String getApplicationVersion() override		{ return ProjectInfo::versionString; }
	void systemRequestedQuit() override					{ quit(); }
    bool moreThanOneInstanceAllowed() override			{ return false; } 

    void initialise(const String& commandLine) override {
        Desktop::getInstance().setOrientationsEnabled(Desktop::allOrientations);
		mainWindow = new MainAppWindow();
    }

    void shutdown() override {
		mainWindow = nullptr; 
    }

	void anotherInstanceStarted(const String& commandLine) override { MessageBox(0, "Only one instance of Injectora should be run at a time!", "Injectora", MB_ICONWARNING); }
    
private:
    ScopedPointer<MainAppWindow> mainWindow;
	LookAndFeel_V3	lookAndFeelV3;
};

START_JUCE_APPLICATION(InjectoraApplication)
