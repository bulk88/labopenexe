// labopen.cpp : Defines the entry point for the console application.
//

#include "tchar.h"
#include "Windows.h"
#include "strsafe.h"
#include <malloc.h>
#define ORIGPATH "href=\"../MASTERS/StdAlneEZclaim modified for Office.pdf\""
#define NEWPATH "href=\"/C/Documents and Settings/Administrator/My Documents/Medical/Medicare Medicaid/MASTERS/"

#define TSTRLEN(x) (_tcslen(x)*sizeof(TCHAR))


void DisplayError(LPTSTR lpszFunction);
char * InplaceCrudeTSTRToAscii(TCHAR * tstr);
int _tmain(int argc, _TCHAR* argv[])
{
    size_t argvlen4;
    if(argc != 5 || (argvlen4 = strlen(InplaceCrudeTSTRToAscii(argv[4]))) != 32) {
	MessageBox( NULL, 
	    _T("usage: labopen.exe \"src xfdf path\" \"plain english lab name\" \"lab pdf path\" \"32 char lab 'original' property XML hex sha1\""),
	    NULL, 
	    MB_ICONSTOP
	);
	return 0;
    }
    HANDLE hFile, hMap;
    DWORD filesize;
    char *p;
    char *newfile;
    char *newfilecursor;
    char *newfilecursor2;
    DWORD dwBytesWritten;
 
    hFile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    { 
        DisplayError(TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to open file \"%s\" for read.\n"), argv[1]);
        return 0; 
    }
    filesize = GetFileSize(hFile, NULL);
    if (filesize == INVALID_FILE_SIZE)
    { 
        DisplayError(TEXT("GetFileSize"));
        return 0; 
    }
    hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if(hMap == NULL) {
        DisplayError(TEXT("CreateFileMapping"));
        return 0; 
    }
    p = (char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if(p == NULL) {
        DisplayError(TEXT("MapViewOfFile"));
        return 0; 
    }
    //convert to ASCII
    size_t argvlen3 = _tcslen(argv[3]);
    newfile = (char*)_alloca(filesize+sizeof(NEWPATH)+argvlen3+argvlen4);
    char * filestart = strstr(p, ORIGPATH);
    if(filestart == NULL) {
	SetLastError(ERROR_INVALID_DATA);
        DisplayError(TEXT("strstr orig pdf path name not matched"));
        return 0; 
    }
    newfilecursor = (char*)((size_t)newfile+(size_t)filestart-(size_t)p);
    //first half of file
    memcpy(newfile, p, filestart-p);
    //add new path header
    memcpy(newfilecursor, NEWPATH, sizeof(NEWPATH)-1);
    newfilecursor += sizeof(NEWPATH)-1;

    newfilecursor2 = newfilecursor + argvlen3;
    //copy .pdf file name
    memcpy(newfilecursor, InplaceCrudeTSTRToAscii(argv[3]), argvlen3);
    //add end quote
    *newfilecursor2 = '"';
    newfilecursor2++;

    size_t last_half_file = filesize-(filestart+sizeof(ORIGPATH)-1-p);
    *(char*)(newfilecursor2+last_half_file) = '\xDD';
    //copy last half of file
    memcpy(newfilecursor2, filestart+sizeof(ORIGPATH)-1, last_half_file);
    *(newfilecursor2+last_half_file) = '\0';
    newfilecursor2 = strstr(newfile, "original=\"");
    if(newfilecursor2 == NULL) {
	SetLastError(ERROR_INVALID_DATA);
        DisplayError(TEXT("strstr orignal SHA1 ID not found"));
        return 0; 
    }
    memcpy(newfilecursor2+sizeof("original=\"")-1, argv[4], 32);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    TCHAR szTempFileName[MAX_PATH];  
    TCHAR lpTempPathBuffer[MAX_PATH];
    DWORD dwRetVal;
    //  Gets the temp path env string (no guarantee it's a valid path).
    dwRetVal = GetTempPath(MAX_PATH,          // length of the buffer
                           lpTempPathBuffer); // buffer for path 
    if (dwRetVal > MAX_PATH || (dwRetVal == 0))
    {
        DisplayError(TEXT("GetTempPath"));
	return 0;
    }

    //  Generates a temporary file name. 
    dwRetVal = GetTempFileName(lpTempPathBuffer, // directory for tmp files
                              TEXT("lab"),     // temp file name prefix 
                              0,                // create unique name 
                              szTempFileName);  // buffer for name 
    if (dwRetVal == 0)
    {
	DisplayError(TEXT("GetTempFileName"));
	return 0;
    }
    //rename .tmp to .xfdf
    memcpy(szTempFileName+(_tcslen(szTempFileName)-3), TEXT("xfdf"), sizeof(TEXT("xfdf")));
    hFile = CreateFile((LPTSTR) szTempFileName, // file name 
                           (GENERIC_READ | GENERIC_WRITE),        // open for write 
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL,                 // default security 
                           CREATE_ALWAYS,        // overwrite existing
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);                // no template 
    if (hFile == INVALID_HANDLE_VALUE) 
    { 
        DisplayError(TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to open file \"%s\" for wrute.\n"), szTempFileName);
        return 0; 
    }
    if (!WriteFile(hFile, 
                            newfile, 
                            (DWORD)strlen(newfile),
                            &dwBytesWritten, 
                            NULL)) 
    {
        DisplayError(TEXT("WriteFile"));
        return 0;
    }
    CloseHandle(hFile);
    HINSTANCE err = ShellExecute(
  NULL,
  TEXT("Open"),
  szTempFileName,
  NULL,
  NULL,
  SW_SHOWNORMAL
);
    if(err <= (HINSTANCE)32) {
	SetLastError((DWORD)err);
	DisplayError(TEXT("ShellExecute"));
    }
    Sleep(5000);
    if (!DeleteFile(szTempFileName)){
        DisplayError(TEXT("DeleteFile"));
        return 0;
    }


    return 0;
}

char * InplaceCrudeTSTRToAscii(TCHAR * tstr) {
    unsigned int i = 0;
    char * origstr = (char *)tstr;
    char * str = (char *)tstr;
    if(sizeof(TCHAR) == 2){
	while(*tstr != 0) {
	    char c = (char)*tstr;
	    *tstr = 0;
	    tstr++;
	    *((char *)str) = c;
	    str++;
	}
	*str ='\0';
    }
    return origstr;
}

void DisplayError(LPTSTR lpszFunction) 
// Routine Description:
// Retrieve and output the system error message for the last-error code
{ 
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, 
        NULL );

    lpDisplayBuf = 
        (LPVOID)LocalAlloc( LMEM_ZEROINIT, 
                            ( lstrlen((LPCTSTR)lpMsgBuf)
                              + lstrlen((LPCTSTR)lpszFunction)
                              + 40) // account for format string
                            * sizeof(TCHAR) );
    
    if (FAILED( StringCchPrintf((LPTSTR)lpDisplayBuf, 
                     LocalSize(lpDisplayBuf) / sizeof(TCHAR),
                     TEXT("%s failed with error code %d as follows:\n%s"), 
                     lpszFunction, 
                     dw, 
                     lpMsgBuf)))
    {
        printf("FATAL ERROR: Unable to output error code.\n");
    }
    
    _tprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}
