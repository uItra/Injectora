/* ==================================== JUCER_BINARY_RESOURCE ====================================

   This is an auto-generated file: Any edits you make may be overwritten!

*/

namespace BinaryData
{

//================== icon.png ==================
static const unsigned char temp_binary_data_0[] = { 137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,32,0,0,0,32,8,6,0,0,0,115,122,122,244,0,0,0,1,115,82,71,66,0,174,206,28,233,0,0,0,4,103,65,77,65,0,0,177,143,11,252,97,5,0,0,0,9,112,72,89,115,0,0,14,196,0,0,14,196,1,149,43,14,27,0,0,1,20,73,68,65,
84,88,71,197,214,209,109,195,48,16,3,80,143,146,81,178,255,20,217,196,225,57,33,162,28,105,91,178,101,25,232,35,90,230,10,234,175,157,230,25,95,23,153,166,15,247,25,33,181,236,129,227,123,143,64,106,217,67,126,192,218,35,144,90,246,180,247,8,164,150,
61,229,7,228,71,32,255,139,158,220,120,105,185,201,191,212,195,235,241,92,184,209,82,220,34,255,127,249,44,142,231,7,240,243,220,33,127,31,158,85,142,151,220,45,33,181,60,194,13,147,187,39,164,150,173,220,40,185,251,18,82,203,22,110,148,220,125,134,212,
178,150,27,37,119,239,32,181,172,225,70,201,221,175,65,106,185,199,141,146,187,223,130,212,114,139,27,37,119,191,7,169,229,26,55,74,238,190,6,82,75,199,141,146,187,175,133,212,50,115,163,228,238,91,32,181,44,185,81,114,247,173,144,90,146,27,37,119,127,
4,82,75,114,195,193,221,30,133,212,146,98,44,254,108,94,53,30,144,90,210,213,227,1,169,101,224,63,12,87,67,154,114,208,120,64,166,98,224,120,64,22,63,12,30,15,200,239,55,55,140,7,228,125,227,1,169,229,72,72,45,199,153,230,55,212,59,64,226,212,174,50,
187,0,0,0,0,73,69,78,68,174,66,96,130,0,0 };

const char* icon_png = (const char*) temp_binary_data_0;

//= == == == == == == == == = demo table data.xml == == == == == == == == ==
static const unsigned char temp_binary_data_2[] =
//"<!-- It's best not to touch anything here, let Injectora generate this for you -->"
"<TABLE_DATA>\r\n"
"	<SETTINGS>\r\n"
"		<SETTING manualMap=\"false\" autoInject=\"false\" nativeWindow=\"false\" process=\"process.exe\"/>\r\n"		
"	</SETTINGS>\r\n"
//"	<!-- Do not touch ANY of the column section, or you'll corrupt your settings file -->"
"	<COLUMNS>\r\n"
"		<COLUMN columnId=\"1\" name=\"DLL\" width=\"150\"/>\r\n"
"		<COLUMN columnId=\"2\" name=\"Size\" width=\"50\"/>\r\n"
"		<COLUMN columnId=\"3\" name=\"Path\" width=\"200\"/>\r\n"
"	</COLUMNS>\r\n"
"	<DATA>\r\n"
"	</DATA>\r\n"
"</TABLE_DATA>";
const char* table_data_xml = (const char*)temp_binary_data_2;


const char* getNamedResource (const char*, int&) throw();
const char* getNamedResource (const char* resourceNameUTF8, int& numBytes) throw()
{
    unsigned int hash = 0;
    if (resourceNameUTF8 != 0)
        while (*resourceNameUTF8 != 0)
            hash = 31 * hash + (unsigned int) *resourceNameUTF8++;

    switch (hash)
    {
        case 0xd4093963:  
			numBytes = 383; 
			return icon_png;
        default: break;
    }

    numBytes = 0;
    return 0;
}

const char* namedResourceList[] =
{
    "icon_png"
};

}
