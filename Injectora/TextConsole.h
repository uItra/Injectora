#ifndef __TEXTCONSOLE_H__
#define __TEXTCONSOLE_H__

#include "JuceHeader.h"

class TextConsole : public TextEditor 
{
public:
	TextConsole() : TextEditor("Console")
	{
		setMultiLine(true);
		setReadOnly(true);
		setSize(550, 300);
	}

	void addLine(const String& text)
	{
		setCaretPosition(getText().length());
		insertTextAtCaret(text);
	}
};


#endif  // __TEXTCONSOLE_H__