#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>

// No shellcode needed for cmd prompt test

// Find process PID by name
DWORD GetProcessPid(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

// Get multiple sensitive process PIDs
DWORD GetLsassPid() { return GetProcessPid("lsass.exe"); }
DWORD GetWinlogonPid() { return GetProcessPid("winlogon.exe"); }
DWORD GetCsrssPid() { return GetProcessPid("csrss.exe"); }
DWORD GetSmsPid() { return GetProcessPid("smss.exe"); }

// Execute harmless payload - just open cmd prompt
void ExecutePayload() {
    __try {
        // Launch cmd.exe - harmless but visible proof of execution
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        if (CreateProcessA(
            "C:\\Windows\\System32\\cmd.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si,
            &pi)) {

            // Close handles but let cmd.exe run
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // If anything fails, just continue
    }

    // Clean exit of our injection thread
    ExitThread(0);
}

// Main payload function - creates SAFE but suspicious call stack then executes shellcode
extern "C" __declspec(dllexport) void VoidFunc() {
    __try {
        // Give EDR time to initialize monitoring for this thread
        Sleep(2000);

        // Get PIDs of sensitive processes (safer approach)
        DWORD lsassPid = GetLsassPid();
        DWORD winlogonPid = GetWinlogonPid();

        // SAFER SUSPICIOUS CALLS - Less likely to crash but still detectable
        // Use minimal access rights to avoid crashes

        // 1. LSASS access - use safer permissions
        if (lsassPid != 0) {
            HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
            if (hLsass) {
                // Just having the handle is suspicious enough
                CloseHandle(hLsass);
            }
            Sleep(500); // Give EDR time to log each event
        }

        // 2. Multiple LSASS attempts (pattern detection)
        for (int i = 0; i < 3; i++) {
            if (lsassPid != 0) {
                HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
                if (hLsass) {
                    CloseHandle(hLsass);
                }
            }
            Sleep(300); // Ensure each call is logged separately
        }

        // 3. Winlogon access
        if (winlogonPid != 0) {
            HANDLE hWinlogon = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
            if (hWinlogon) {
                CloseHandle(hWinlogon);
            }
            Sleep(300);
        }

        // 4. Safe system reconnaissance calls
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        Sleep(300);

        // 5. Suspicious memory allocation pattern
        LPVOID testMem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (testMem) {
            VirtualFree(testMem, 0, MEM_RELEASE);
        }
        Sleep(300);

        // Give EDR plenty of time to capture all the suspicious activity
        Sleep(3000);

        // NOW execute the harmless payload (separate from suspicious calls)
        ExecutePayload();

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // If anything crashes, exit gracefully
        ExitThread(0);
    }

    // Shouldn't reach here, but safety net
    ExitThread(0);
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        // DLL loaded successfully
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}