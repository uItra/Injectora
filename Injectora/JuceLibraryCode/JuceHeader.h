/*

    IMPORTANT! This file is auto-generated each time you save your
    project - if you alter its contents, your changes may be overwritten!

    This is the header file that your files should include in order to get all the
    JUCE library headers. You should avoid including the JUCE headers directly in
    your own source files, because that wouldn't pick up the correct configuration
    options for your app.

*/

#ifndef __APPHEADERFILE__
#define __APPHEADERFILE__

//#ifdef _DEBUG

#ifndef DEBUG_MESSAGES_ENABLED
#define DEBUG_MESSAGES_ENABLED
#endif

#ifndef WRITE_DEBUG_TO_FILE
#define WRITE_DEBUG_TO_FILE
#endif

//#endif

#include <Windows.h>
#include <string>
#include <fstream>
#include <algorithm>
#include <list>
#include <memory>
#include <TlHelp32.h>
#include <vector>
#include <exception>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include "AppConfig.h"

#include "modules/juce_core/juce_core.h"
#include "modules/juce_cryptography/juce_cryptography.h"
#include "modules/juce_data_structures/juce_data_structures.h"
#include "modules/juce_events/juce_events.h"
#include "modules/juce_graphics/juce_graphics.h"
#include "modules/juce_gui_basics/juce_gui_basics.h"
#include "modules/juce_gui_extra/juce_gui_extra.h"
#include "modules/juce_opengl/juce_opengl.h"
#include "BinaryData.h"

#if ! DONT_SET_USING_JUCE_NAMESPACE
 // If your code uses a lot of JUCE classes, then this will obviously save you
 // a lot of typing, but can be disabled by setting DONT_SET_USING_JUCE_NAMESPACE.
 using namespace juce;
#endif

namespace ProjectInfo
{
    const char* const  projectName    = "Injectora";
    const char* const  versionString  = "0.5b";
    const int          versionNumber  = 0x10000;
}

#endif   // __APPHEADERFILE__
