#include "MainAppWindow.h"

MainAppWindow::MainAppWindow() : DocumentWindow(JUCEApplication::getInstance()->getApplicationName(), Colours::white, DocumentWindow::closeButton | DocumentWindow::minimiseButton)
{
	mainComponent = new MainComponent();
	setResizable(true, false);
	setResizeLimits(350, 200, 40000, 40000);
	setContentOwned(mainComponent, true);
	centreWithSize(getWidth(), getHeight());
	setVisible(true); 
	addKeyListener(getApplicationCommandManager()->getKeyMappings());
	triggerAsyncUpdate();
}

MainAppWindow::~MainAppWindow()
{
	mainComponent = nullptr;
}

void MainAppWindow::closeButtonPressed()
{
	JUCEApplication::getInstance()->systemRequestedQuit();
}

void MainAppWindow::handleAsyncUpdate()
{
	// This registers all of our commands with the command manager
	ApplicationCommandManager* commandManager = getApplicationCommandManager();
	commandManager->registerAllCommandsForTarget(mainComponent);
	commandManager->registerAllCommandsForTarget(JUCEApplication::getInstance());
}