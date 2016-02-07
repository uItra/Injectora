#include "AboutWindow.h"

AboutWindow::AboutWindow() : DocumentWindow("About", Colours::white, DocumentWindow::closeButton)
{
	aboutComponent = new AboutComponent();
	setContentOwned(aboutComponent, true);
	centreWithSize(getWidth(), getHeight());
	setVisible(false);
}

AboutWindow::~AboutWindow()
{
	aboutComponent = nullptr;
}

void AboutWindow::closeButtonPressed()
{
	setVisible(false);
}