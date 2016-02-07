#ifndef __UTILS_H__
#define __UTILS_H__

#include "JuceHeader.h"
#include <fcntl.h>
#include <io.h>
#include"nt_ddk.h"

class Utils
{
public:
	BOOL IsElevated();
	void EnableDebugPrivleges();

	void CreateDebugConsole(LPCSTR lPConsoleTitle);
	void cls(bool clear);

	char* deblank(char *str);
	char* deblank_left(char *str);
	char* deblank_right(char *str);

	BOOL DoesDirectoryExist(const char* path);
	void CreateDirectoryIfNeeded(const char* path);
};

extern Utils utils;

#endif