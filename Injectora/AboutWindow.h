#ifndef __ABOUT_WINDOW_H__
#define __ABOUT_WINDOW_H__

#include "AboutComponent.h"

class AboutWindow : public DocumentWindow
{
public:
	AboutWindow();
	~AboutWindow();

	void closeButtonPressed();

private:
	ScopedPointer<AboutComponent> aboutComponent;

	JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AboutWindow)
};

#endif // __ABOUT_APP_WINDOW_H__