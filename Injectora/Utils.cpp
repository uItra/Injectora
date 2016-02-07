#include "Utils.h"

Utils utils;

void Utils::EnableDebugPrivleges()
{
	HANDLE              hToken;
	LUID                SeDebugNameValue;
	TOKEN_PRIVILEGES    TokenPrivileges;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &SeDebugNameValue))
		{
			TokenPrivileges.PrivilegeCount = 1;
			TokenPrivileges.Privileges[0].Luid = SeDebugNameValue;
			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			{
				CloseHandle(hToken);
				throw std::exception("Couldn't adjust token privileges!");
			}
		}
		else
		{
			CloseHandle(hToken);
			throw std::exception("Couldn't look up privilege value!");
		}
	}
	else
		throw std::exception("Couldn't open process token!");
}


BOOL Utils::IsElevated()
{
	BOOL fRet = false;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
			fRet = Elevation.TokenIsElevated;
	}
	if (hToken)
		CloseHandle(hToken);
	return fRet;
}

char* Utils::deblank(char *str)
{
	char *out = str, *put = str;
	for (; *str != '\0'; ++str)
	{
		if (*str != ' ')
			*put++ = *str;
	}
	*put = '\0';

	return out;
}

char* Utils::deblank_left(char *str)
{
	char *out = str, *put = str;
	for (; *str == ' '; ++str)
	{
		if (*str != ' ')
			break;//*put++ = *str;
	}

	for (; *str != ' '; ++str)
	{
		if (*str != ' ')
			*put++ = *str;
	}

	*put = '\0';

	return out;
}

char* Utils::deblank_right(char *str)
{
	char *out = str, *put = str;
	for (; *str != '\0'; ++str)
	{
		if (*str != ' ')
			*put++ = *str;
	}
	*put = '\0';

	return out;
}

void Utils::CreateDebugConsole(LPCSTR lPConsoleTitle)
{
	HANDLE lStdHandle = 0;
	int hConHandle = 0;
	FILE *fp = 0;
	AllocConsole();
	lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
	SetConsoleTitleA(lPConsoleTitle);
	SetConsoleTextAttribute(lStdHandle, FOREGROUND_RED | FOREGROUND_BLUE | BACKGROUND_RED | BACKGROUND_BLUE | BACKGROUND_GREEN);
	fp = _fdopen(hConHandle, "w");
	*stdout = *fp;
	setvbuf(stdout, NULL, _IONBF, 0);
}

void Utils::cls(bool clear = true)
{
	COORD			coordScreen = { 0, 0 };    /* here's where we'll home the cursor */
	unsigned long	cCharsWritten;

	/* fill the entire screen with blanks */
	if (clear)
	{
		FillConsoleOutputCharacter(GetStdHandle(STD_OUTPUT_HANDLE), ' ', 150, coordScreen, &cCharsWritten);
	}
	/* put the cursor at (0, 0) */
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coordScreen);
}

BOOL Utils::DoesDirectoryExist(const char* path)
{
	DWORD dwAttributes = GetFileAttributes(path);
	if (dwAttributes == INVALID_FILE_ATTRIBUTES)
		return false;
	return (dwAttributes & FILE_ATTRIBUTE_DIRECTORY);
}

void Utils::CreateDirectoryIfNeeded(const char* path)
{
	if (!DoesDirectoryExist(path))
	{
		CreateDirectory(path, NULL);
	}
}