#ifndef __ABOUT_COMPONENT_H__
#define __ABOUT_COMPONENT_H__

#include "JuceHeader.h"

class AboutComponent : public Component
{
public:
	AboutComponent()
	{
		cachedImage_icon_png = ImageCache::getFromMemory(BinaryData::icon_png, BinaryData::icon_pngSize);
		addAndMakeVisible(groupComponent = new GroupComponent("new group", TRANS("About")));
		groupComponent->setColour(GroupComponent::outlineColourId, Colour(0xffff2f2f));
		groupComponent->setColour(GroupComponent::textColourId, Colours::black);
		groupComponent->setBounds(12, 8, 576, 580);

		addAndMakeVisible(infoLabel = new TextEditor("system info label"));

		infoLabel->setFont(Font(Font::getDefaultSansSerifFontName(), 15.00f, Font::plain));
		infoLabel->setMultiLine(true);
		//infoLabel->setJustificationType(Justification::topLeft);
		//infoLabel->setEditable(true, false, false);
		infoLabel->setColour(TextEditor::textColourId, Colours::black);
		infoLabel->setColour(TextEditor::backgroundColourId, Colour(0x00000000));
		infoLabel->setColour(TextEditor::focusedOutlineColourId, Colour(0x00000000));
		int newheight;
		infoLabel->setText(getAllSystemInfo(&newheight), dontSendNotification);
		infoLabel->setBounds(24, 88, 552, 488);

		groupComponent->setSize(groupComponent->getWidth(), newheight - 25);

		setSize(600, newheight);
	}

	~AboutComponent()
	{
		groupComponent = nullptr;
		infoLabel = nullptr;
	}

	void paint(Graphics& g)
	{
		g.fillAll(Colours::white);

		g.setColour(Colours::black);
		g.drawImage(cachedImage_icon_png, 76, 26, 38, 38, 0, 0, cachedImage_icon_png.getWidth(), cachedImage_icon_png.getHeight());

		g.setColour(Colour(0xffc00000));
		g.setFont(Font("Verdana", 15.00f, Font::bold));
		g.drawText(TRANS("Injectora by dude719"), 112, 26, 192, 36, Justification::centred, true);

		g.setColour(Colour(0xffd60000));
		g.fillRect(55, 74, 489, 2);

		g.setColour(Colours::black);
		g.setFont(Font(15.00f, Font::plain));

		char version[128];
		#if defined _WIN64
		sprintf_s(version, "Version: %s x64", ProjectInfo::versionString);
		g.drawText(TRANS(version), 324, 22, 200, 30, Justification::centredLeft, true);
		#else
		sprintf_s(version, "Version: %s", ProjectInfo::versionString);
		g.drawText(TRANS(version), 324, 22, 200, 30, Justification::centredLeft, true);
		#endif

		g.setColour(Colours::black);
		g.setFont(Font(15.00f, Font::plain));
		
		char buildDate[64];
		sprintf_s(buildDate, "Built on: %s", "Februrary 2nd, 2016");

		g.drawText(TRANS(buildDate), 324, 42, 200, 30, Justification::centredLeft, true);
	}

	void resized()
	{
		groupComponent->setTopLeftPosition(12, 8); // , 576, 580
		infoLabel->setTopLeftPosition(24, 88); // , 552, 488
	}

	static const char* getDisplayOrientation()
	{
		switch (Desktop::getInstance().getCurrentOrientation())
		{
		case Desktop::upright:              return "Upright";
		case Desktop::upsideDown:           return "Upside-down";
		case Desktop::rotatedClockwise:     return "Rotated Clockwise";
		case Desktop::rotatedAntiClockwise: return "Rotated Anti-clockwise";
		default: jassertfalse; break;
		}
		return nullptr;
	}

	static String getDisplayInfo(int* newHeight)
	{
		const Desktop::Displays& displays = Desktop::getInstance().getDisplays();
		String displayDesc;
		for (int i = 0; i < displays.displays.size(); ++i)
		{
			const Desktop::Displays::Display display = displays.displays.getReference(i);
			displayDesc << "Display " << (i + 1) << (display.isMain ? " (main)" : "") << ":" << newLine; *newHeight += 15;
			displayDesc << "  Area: " << display.totalArea.toString() << newLine; *newHeight += 15;
			displayDesc << "  DPI: " << display.dpi << newLine; *newHeight += 15;
			displayDesc << "  Scale: " << display.scale << newLine; *newHeight += 15;
			displayDesc << newLine; *newHeight += 15;
		}
		//displayDesc << "Orientation: " << getDisplayOrientation() << newLine;
		return displayDesc;
	}

	static String getMacAddressList(int* newHeight)
	{
		Array<MACAddress> macAddresses;
		MACAddress::findAllAddresses(macAddresses);
		String addressList;
		for (int i = 0; i < macAddresses.size(); ++i)
			addressList << "   " << macAddresses[i].toString() << newLine; *newHeight += 15;
		return addressList;
	}

	static String getFileSystemRoots()
	{
		Array<File> roots;
		File::findFileSystemRoots(roots);
		StringArray rootList;
		for (int i = 0; i < roots.size(); ++i)
			rootList.add(roots[i].getFullPathName());
		return rootList.joinIntoString(", ");
	}

	static String getAllSystemInfo(int* newHeight)
	{
		int newAboutWindowHeight = 150;
		const char* osArchitecture = SystemStats::isOperatingSystem64Bit() ? " x64" : " x32";
		String systemInfo;
		systemInfo << "Time and date:    " << Time::getCurrentTime().toString(true, true, true, false) << newLine; newAboutWindowHeight += 15;
		systemInfo << "System up-time:   " << RelativeTime::milliseconds((int64)Time::getMillisecondCounterHiRes()).getDescription() << newLine; newAboutWindowHeight += 15;
		systemInfo << newLine; newAboutWindowHeight += 15;
		systemInfo << "Operating system: " << SystemStats::getOperatingSystemName() << osArchitecture << newLine; newAboutWindowHeight += 15;
		systemInfo << "Host name:        " << SystemStats::getComputerName() << newLine; newAboutWindowHeight += 15;
		#if !defined JUCE_WINDOWS
		systemInfo << "Device type:      " << SystemStats::getDeviceDescription() << newLine; newAboutWindowHeight += 15;
		#endif
		systemInfo << "User logon name:  " << SystemStats::getLogonName() << newLine; newAboutWindowHeight += 15;
		systemInfo << "Full user name:   " << SystemStats::getFullUserName() << newLine; newAboutWindowHeight += 15;
		systemInfo << "User region:      " << SystemStats::getUserRegion() << newLine; newAboutWindowHeight += 15;
		systemInfo << "User language:    " << SystemStats::getUserLanguage() << newLine; newAboutWindowHeight += 15;
		systemInfo << "Display language: " << SystemStats::getDisplayLanguage() << newLine; newAboutWindowHeight += 15;
		systemInfo << newLine; newAboutWindowHeight += 15;
		systemInfo << "Number of CPUs: " << SystemStats::getNumCpus() << newLine; newAboutWindowHeight += 15;
		systemInfo << "Memory size:    " << SystemStats::getMemorySizeInMegabytes() << " MB" << newLine; newAboutWindowHeight += 15;
		systemInfo << "CPU vendor:     " << SystemStats::getCpuVendor() << newLine; newAboutWindowHeight += 15;
		systemInfo << "CPU speed:      " << SystemStats::getCpuSpeedInMegaherz() << " MHz" << newLine; newAboutWindowHeight += 15;
		systemInfo << "CPU has MMX:    " << (SystemStats::hasMMX() ? "true" : "false") << newLine; newAboutWindowHeight += 15;
		systemInfo << "CPU has SSE:    " << (SystemStats::hasSSE() ? "true" : "false") << newLine; newAboutWindowHeight += 15;
		systemInfo << "CPU has SSE2:   " << (SystemStats::hasSSE2() ? "true" : "false") << newLine; newAboutWindowHeight += 15;
		systemInfo << "CPU has SSE3:   " << (SystemStats::hasSSE3() ? "true" : "false") << newLine; newAboutWindowHeight += 15;
		systemInfo << newLine; newAboutWindowHeight += 15;
		systemInfo << "File System roots: " << getFileSystemRoots() << newLine; newAboutWindowHeight += 15;
		systemInfo << "Free space in home folder: " << File::descriptionOfSizeInBytes(File::getSpecialLocation(File::userHomeDirectory).getBytesFreeOnVolume()) << newLine; newAboutWindowHeight += 15;
		systemInfo << newLine; newAboutWindowHeight += 15;
		systemInfo << getDisplayInfo(&newAboutWindowHeight);
		systemInfo << "Network card MAC addresses: " << newLine; newAboutWindowHeight += 15;
		systemInfo << getMacAddressList(&newAboutWindowHeight) << newLine; newAboutWindowHeight += 15;

		*newHeight = newAboutWindowHeight;

		return systemInfo;
	}

private:
	Image cachedImage_icon_png;
	ScopedPointer<GroupComponent> groupComponent;
	ScopedPointer<TextEditor> infoLabel;

	JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(AboutComponent)
};

#endif   // __ABOUT_COMPONENT_H__