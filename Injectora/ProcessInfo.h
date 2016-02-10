#pragma once

#include "JuceHeader.h"

class ProcessInfo //: public Component
{
public:
	ProcessInfo() : processName(String::empty), processId(0)
	{
	}

	~ProcessInfo()
	{
		processId = NULL;
	}

	String toString()
	{
		String processText(processName);
		processText += "  ( ";
		processText += String((unsigned int)processId);
		processText += " )";
		return processText;
	}

	String processName;
	DWORD processId;

	class ProcessNameSorter
	{
	public:
		static int compareElements(ProcessInfo a, ProcessInfo b) {
			return a.processName.compareIgnoreCase(b.processName);
		}
	};

	class ProcessIdSorter
	{
	public:
		static int compareElements(ProcessInfo first, ProcessInfo second) {
			return (first.processId < second.processId) ? -1 : ((second.processId < first.processId) ? 1 : 0);
		}
	};

};