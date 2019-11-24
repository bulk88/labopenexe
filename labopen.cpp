// labopen.cpp : Defines the entry point for the console application.
//


#include "tchar.h"
#include "Windows.h"
#include "strsafe.h"
#include <malloc.h>
#include "shlwapi.h"
#pragma intrinsic(memcpy)
#define ORIGPATH "href=\"../MASTERS/StdAlneEZclaim modified for Office.pdf\""
#define NEWPATH "href=\"/C/Documents and Settings/Administrator/My Documents/Medical/Medicare Medicaid/MASTERS/"

#ifdef _UNICODE
#  define InplaceCrudeTSTRToAscii(x) InplaceCrudeWSTRToAscii(x)
#  define InplaceCrudeWSTRToTSTR(x) (x)
#else
#  define InplaceCrudeTSTRToAscii(x) (x)
#  define InplaceCrudeWSTRToTSTR(x) InplaceCrudeWSTRToAscii(x)
#endif


void DisplayError(LPTSTR lpszFunction);
char * InplaceCrudeWSTRToAscii(LPWSTR wstr);
void WINAPI LazyMessageBox(LPCTSTR str);
LPTSTR GetFormattedMessage(LPCTSTR pMessage, ...);

int WinMainNoCRT(void) {
   LPWSTR *argv;
    int argc;
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    size_t argvlen4;
    if(argc != 5 || (argvlen4 = lstrlenA(InplaceCrudeWSTRToAscii(argv[4]))) != 32) {
	LazyMessageBox(_T("usage: labopen.exe \"src xfdf path\" \"plain english lab name\" \"lab pdf path\" \"32 char lab 'original' property XML hex sha1\""));
	return 0;
    }
    HANDLE hFile, hMap;
    DWORD filesize;
    char *p;
    char *newfile;
    char *newfilecursor;
    char *newfilecursor2;
    DWORD dwBytesWritten;
 
    hFile = CreateFile(InplaceCrudeWSTRToTSTR(argv[1]), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    { 
        DisplayError(TEXT("CreateFile"));
	LPWSTR msg = GetFormattedMessage(TEXT("Terminal failure: unable to open file \"%1!s!\" for read."), argv[1]);
        LazyMessageBox(msg);
	LocalFree(msg);
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
    size_t argvlen3 = lstrlenA(InplaceCrudeWSTRToAscii(argv[3]));
    newfile = (char*)_alloca(filesize+sizeof(NEWPATH)+argvlen3+argvlen4);
    char * filestart = StrStrA(p, ORIGPATH);
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
    memcpy(newfilecursor, argv[3], argvlen3);
    //add end quote
    *newfilecursor2 = '"';
    newfilecursor2++;

    size_t last_half_file = filesize-(filestart+sizeof(ORIGPATH)-1-p);
    *(char*)(newfilecursor2+last_half_file) = '\xDD';
    //copy last half of file
    memcpy(newfilecursor2, filestart+sizeof(ORIGPATH)-1, last_half_file);
    *(newfilecursor2+last_half_file) = '\0';
    newfilecursor2 = StrStrA(newfile, "original=\"");
    if(newfilecursor2 == NULL) {
	SetLastError(ERROR_INVALID_DATA);
        DisplayError(TEXT("strstr orignal SHA1 ID not found"));
        return 0; 
    }
    memcpy(newfilecursor2+sizeof("original=\"")-1, argv[4], 32);
    CloseHandle(hMap);
    CloseHandle(hFile);
    LocalFree(argv);
    
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
    memcpy(szTempFileName+(lstrlen(szTempFileName)-3), TEXT("xfdf"), sizeof(TEXT("xfdf")));
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
	LPWSTR msg = GetFormattedMessage(TEXT("Terminal failure: unable to open file \"%1!s!\" for write."), szTempFileName);
        LazyMessageBox(msg);
	LocalFree(msg);
        return 0; 
    }
    if (!WriteFile(hFile, 
                            newfile, 
                            (DWORD)lstrlenA(newfile),
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

char * InplaceCrudeWSTRToAscii(LPWSTR wstr) {
    unsigned int i = 0;
    char * origstr = (char *)wstr;
    char * str = (char *)wstr;
    while(*wstr != 0) {
	char c = (char)*wstr;
	*wstr = 0;
	wstr++;
	*((char *)str) = c;
	str++;
    }
    *str ='\0';
    return origstr;
}

void DisplayError(LPTSTR lpszFunction) 
// Routine Description:
// Retrieve and output the system error message for the last-error code
{ 
    LPTSTR lpMsgBuf;
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

    LPWSTR msg =
	GetFormattedMessage(
	    TEXT("ERROR: %1!s! failed with error code %2!d! as follows:\n%3!s!"),
	    lpszFunction, 
	    dw, 
	    lpMsgBuf
        );
    
    LazyMessageBox(msg);

    LocalFree(lpMsgBuf);
    LocalFree(msg);
}

void
WINAPI
LazyMessageBox(LPCTSTR str) {
    HMODULE module = LoadLibrary(_T("user32.dll"));
#ifdef UNICODE
 int (WINAPI * pfnMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT) = (int (WINAPI *)(HWND, LPCTSTR, LPCTSTR, UINT)) GetProcAddress(module, "MessageBoxW");
#else
 int (WINAPI * pfnMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT) pfnMessageBox = (int (WINAPI *)(HWND, LPCTSTR, LPCTSTR, UINT)) GetProcAddress(module, "MessageBoxA");
#endif
 pfnMessageBox(NULL, str, NULL, MB_ICONSTOP);
 return;
}

// Formats a message string using the specified message and variable
// list of arguments.
LPTSTR GetFormattedMessage(LPCTSTR pMessage, ...)
{
    LPTSTR pBuffer = NULL;

    va_list args = NULL;
    va_start(args, pMessage);

    FormatMessage(FORMAT_MESSAGE_FROM_STRING |
                  FORMAT_MESSAGE_ALLOCATE_BUFFER,
                  pMessage, 
                  0,
                  0,
                  (LPWSTR)&pBuffer, 
                  0, 
                  &args);

    va_end(args);

    return pBuffer;
}