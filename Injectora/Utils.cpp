#include "Utils.h"
//
//char* Utils::deblank(char *str)
//{
//	char *out = str, *put = str;
//	for (; *str != '\0'; ++str)
//	{
//		if (*str != ' ')
//			*put++ = *str;
//	}
//	*put = '\0';
//
//	return out;
//}
//
//char* Utils::deblank_left(char *str)
//{
//	char *out = str, *put = str;
//	for (; *str == ' '; ++str)
//	{
//		if (*str != ' ')
//			break;//*put++ = *str;
//	}
//
//	for (; *str != ' '; ++str)
//	{
//		if (*str != ' ')
//			*put++ = *str;
//	}
//
//	*put = '\0';
//
//	return out;
//}
//
//char* Utils::deblank_right(char *str)
//{
//	char *out = str, *put = str;
//	for (; *str != '\0'; ++str)
//	{
//		if (*str != ' ')
//			*put++ = *str;
//	}
//	*put = '\0';
//
//	return out;
//}