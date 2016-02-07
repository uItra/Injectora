#ifndef __TABLE_COMPONENT_H__
#define __TABLE_COMPONENT_H__

#include "../JuceLibraryCode/JuceHeader.h"

class MainComponent;

struct ProcessInfo
{
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


extern ScopedPointer<TextEditor>	processEditor;
extern ScopedPointer<Component>		dllComponent;

class TableComponent : public Component, public TableListBoxModel
{
public:
    TableComponent() : font(12.0f)
    {
        addAndMakeVisible(table);
        table.setModel(this);
        table.setColour(ListBox::outlineColourId, Colours::black);
		table.setColour(ListBox::backgroundColourId, Colours::white);
		table.setColour(ListBox::textColourId, Colours::black);
		table.getVerticalScrollBar()->setColour(ScrollBar::thumbColourId, Colours::white);
		table.getHorizontalScrollBar()->setColour(ScrollBar::thumbColourId, Colours::white);
        table.setOutlineThickness(1);
		table.setRowHeight(15);
		table.getHeader().setSize(0, 15);
		table.setMultipleSelectionEnabled(false);
    }

    ~TableComponent()
    {
		if (tableData != nullptr)
			delete tableData;
    }

	int getNumRows() override
	{
		return numRows;
	}

	void selectedRowsChanged(int lastRowSelected) override
	{
		if (numRows > 0)
		{
			if (xml)
			{
				XmlElement* rowElement = dataList->getChildElement(lastRowSelected);
				currentDll = rowElement->getStringAttribute(getAttributeNameForColumnId(3));
				dllComponent->setName(currentDll);
			}
			else
			{
				currentProcess = processList[lastRowSelected].processName;
				processEditor->setText(currentProcess);
			}
		}
	}

	void sortOrderChanged(int newSortColumnId, bool isForwards) override
	{
		if (newSortColumnId != 0)
		{
			if (xml)
			{
				XmlDataSorter sorter(getAttributeNameForColumnId(newSortColumnId), isForwards);
				dataList->sortChildElements(sorter);
				table.updateContent();
			}
			else
			{
				if (newSortColumnId == 1) 
				{
					ProcessInfo::ProcessNameSorter nameSort;
					processList.sort(nameSort);
				}
				else if (newSortColumnId == 2)
				{
					ProcessInfo::ProcessIdSorter pidSort;
					processList.sort(pidSort);
				}

				if (!isForwards)
				{
					Array<ProcessInfo> temp;
					for (int i = processList.size() - 1; i >= 0; i--)
						temp.add(processList[i]);
					processList.swapWith(temp);
					temp.clear();
				}

				table.updateContent();
			}
		}
	}

	void paintRowBackground(Graphics& g, int rowNumber, int width, int height, bool rowIsSelected) override
	{
		if (numRows > 0)
		{
			if (rowIsSelected)
				g.fillAll(Colour(0xffb00000));
		}
	}

	void paintCell(Graphics& g, int rowNumber, int columnId, int width, int height, bool rowIsSelected) override
	{
		g.setColour(rowIsSelected ? Colours::white : Colours::black);
		g.setFont(font);
		if (xml)
		{
			XmlElement* rowElement = dataList->getChildElement(rowNumber);
			if (rowElement != 0)
			{
				const String text(rowElement->getStringAttribute(getAttributeNameForColumnId(columnId)));
				g.drawText(text, 2, 0, width - 4, height, Justification::centredLeft, true);
			}
		}
		else
		{
			if (columnId == 1)
			{
				const String rowItem = processList[rowNumber].processName;
				if (rowItem.isNotEmpty())
					g.drawText("   " + rowItem, 2, 0, width - 4, height, Justification::centredLeft, true);
			}
			else if (columnId == 2)
			{
				const DWORD pid = processList[rowNumber].processId;
				char rowItem[256];
				sprintf_s(rowItem, "   %i", pid);
				g.drawText(rowItem, 2, 0, width - 4, height, Justification::centredLeft, true);
			}
		}
		g.setColour(Colours::black.withAlpha(0.2f));
		g.fillRect(width - 1, 0, 1, height);
	}

	String getAttributeNameForColumnId(const int columnId) const
	{
		forEachXmlChildElement(*columnList, columnXml)
		{
			if (columnXml->getIntAttribute("columnId") == columnId)
				return columnXml->getStringAttribute("name");
		}
		return String::empty;
	}

	void deleteKeyPressed(int currentSelectedRow)
	{
		if (xml)
		{
			if (numRows > 0)
			{
				dataList->removeChildElement(dataList->getChildElement(currentSelectedRow), true);
				numRows--;
				table.updateContent();
			}
		}
		else
		{
			if (processList.size() > 0)
			{
				processList.remove(currentSelectedRow);
				numRows--;
				table.updateContent();
			}
		}
	}

    void paint (Graphics& g)
    {
    }

	void resized() override
	{
		table.setBoundsInset(BorderSize<int>(8));
	}

    TableListBox table;     // the table component itself
    Font font;
	int numRows;

	XmlElement* tableData;   // This is the XML document loaded from the embedded file "demo table data.xml"
	XmlElement* columnList; // A pointer to the sub-node of demoData that contains the list of columns
	XmlElement* dataList;

	bool xml;
	Array<ProcessInfo> processList;
	String currentDll;
	String currentProcess;

	String openFile()
	{
		char szDir[MAX_PATH];
		GetModuleFileName(NULL, szDir, MAX_PATH);
		String myDir = szDir;
		myDir = myDir.upToLastOccurrenceOf(".", false, true);
		File file(myDir + "_settings.xml");
		if (file.exists())
		{
			//printf("Exists!\n");
			return file.loadFileAsString();
		}
		else
		{
			//printf("Doesn't Exist!\n");
			return String::empty;
		}
	}

	void setProcessList(Array<ProcessInfo> list)
	{
		processList.clear();
		processList = list;
	}

	class StringDataSorter
	{
	public:
		static bool compareNoCaseAscending(String first, String second)
		{
			int i = 0;
			while ((i < first.length()) && (i < second.length()))
			{
				if (tolower(first[i]) < tolower(second[i])) return true;
				else return false;
				i++;
			}
			if (first.length() < second.length()) return true;
			else return false;
		}

		static bool compareNoCaseDescending(String first, String second)
		{
			int i = 0;
			while ((i < first.length()) && (i < second.length()))
			{
				if (tolower(first[i]) < tolower(second[i])) return false;
				else return true;
				i++;
			}
			if (first.length() < second.length()) return false;
			else return true;
		}
	};

	class XmlDataSorter
	{
	public:
		XmlDataSorter(const String attributeToSort_, bool forwards) : attributeToSort(attributeToSort_), direction(forwards ? 1 : -1)
		{
		}

		int compareElements(XmlElement* first, XmlElement* second) const
		{
			int result = first->getStringAttribute(attributeToSort).compareLexicographically(second->getStringAttribute(attributeToSort));
			if (result == 0)
				result = first->getStringAttribute("ID").compareLexicographically(second->getStringAttribute("ID"));
			return direction * result;
		}
	private:
		String attributeToSort;
		int direction;
	};

	void loadData(bool isXml)
	{
		if (isXml)
		{
			String data = openFile();
			if (data != String::empty)
			{
				XmlDocument dataDoc(data);
				tableData = dataDoc.getDocumentElement();
			}
			else
			{
				XmlDocument dataDoc(String((const char*)BinaryData::table_data_xml));
				tableData = dataDoc.getDocumentElement();
			}

			dataList = tableData->getChildByName("DATA");
			columnList = tableData->getChildByName("COLUMNS");
			numRows = dataList->getNumChildElements();

			xml = true;
		}
		else
		{
			xml = false;
			tableData = nullptr;
			dataList = nullptr;
			columnList = nullptr;
			numRows = processList.size();
		}
	}

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(TableComponent)
};


#endif  // __TABLE_COMPONENT_H__
