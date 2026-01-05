#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* PfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS(NTAPI* PfnNtQueryObject)(
    HANDLE,
    OBJECT_INFORMATION_CLASS,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS(NTAPI* PfnNtDuplicateObject)(
    HANDLE,
    HANDLE,
    HANDLE,
    PHANDLE,
    ACCESS_MASK,
    ULONG,
    ULONG
    );

typedef NTSTATUS(NTAPI* PfnNtMapViewOfSection)(
    HANDLE,
    HANDLE,
    PVOID*,
    ULONG_PTR,
    SIZE_T,
    PLARGE_INTEGER,
    PSIZE_T,
    SECTION_INHERIT,
    ULONG,
    ULONG
    );

typedef NTSTATUS(NTAPI* PfnNtUnmapViewOfSection)(
    HANDLE,
    PVOID
    );

namespace proc {

    DWORD FindByName(const wchar_t* Name) {
        PROCESSENTRY32W Pe{};
        Pe.dwSize = sizeof(Pe);

        HANDLE HSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (HSnap == INVALID_HANDLE_VALUE)
            return 0;

        if (::Process32FirstW(HSnap, &Pe)) {
            do {
                if (!::_wcsicmp(Pe.szExeFile, Name)) {
                    ::CloseHandle(HSnap);
                    return Pe.th32ProcessID;
                }
            } while (::Process32NextW(HSnap, &Pe));
        }

        ::CloseHandle(HSnap);
        return 0;
    }

}

namespace obj {

    std::wstring GetType(HANDLE H) {
        static PfnNtQueryObject NtQueryObject =
        (PfnNtQueryObject)::GetProcAddress(::GetModuleHandleW(L"ntdll"), "NtQueryObject");

        ULONG Len = 4096;
        std::vector<BYTE> Buf(Len);

        // ntdll!NtQueryObject -> ObjectTypeInformation (2)
        NTSTATUS Status = NtQueryObject(H, (OBJECT_INFORMATION_CLASS)2, Buf.data(), Len, &Len);
        if (!NT_SUCCESS(Status))
            return L"";

        PUNICODE_STRING TypeName = (PUNICODE_STRING)Buf.data();
        if (!TypeName->Buffer || !TypeName->Length)
            return L"";

        return std::wstring(TypeName->Buffer, TypeName->Length / sizeof(WCHAR));
    }

}

namespace section {

    std::wstring GetFileName(HANDLE HSection) {
        static PfnNtMapViewOfSection NtMapViewOfSection =
         (PfnNtMapViewOfSection)::GetProcAddress(::GetModuleHandleW(L"ntdll"), "NtMapViewOfSection");

        static PfnNtUnmapViewOfSection NtUnmapViewOfSection =
        (PfnNtUnmapViewOfSection)::GetProcAddress(::GetModuleHandleW(L"ntdll"), "NtUnmapViewOfSection");

        PVOID Base = nullptr;
        SIZE_T ViewSize = 0;

        NTSTATUS Status = NtMapViewOfSection(
            HSection,
            ::GetCurrentProcess(),
            &Base,
            0,
            0,
            nullptr,
            &ViewSize,
            ViewShare,
            0,
            PAGE_READONLY
        );

        if (!NT_SUCCESS(Status))
            return L"";

        WCHAR DevicePath[MAX_PATH * 2]{};

        DWORD Result = ::GetMappedFileNameW(::GetCurrentProcess(), Base, DevicePath, MAX_PATH * 2);

        NtUnmapViewOfSection(::GetCurrentProcess(), Base);

        if (!Result)
         return L"";

        std::wstring Path = DevicePath;
        WCHAR Drives[512];
        if (::GetLogicalDriveStringsW(512, Drives)) {
            WCHAR* Drive = Drives;
            while (*Drive) {
                WCHAR DevName[MAX_PATH];
                WCHAR Letter[3] = { Drive[0], L':', 0 };
                if (::QueryDosDeviceW(Letter, DevName, MAX_PATH)) {
                    SIZE_T DevLen = ::wcslen(DevName);
                    if (Path.size() >= DevLen && ::_wcsnicmp(Path.c_str(), DevName, DevLen) == 0) {
                        Path = std::wstring(Letter) + Path.substr(DevLen);
                        break;
                    }
                }
                Drive += ::wcslen(Drive) + 1;
            }
        }

        return Path;
    }

}

namespace str {

    std::wstring Lower(const std::wstring& S) {
        std::wstring Result = S;
        std::transform(Result.begin(), Result.end(), Result.begin(), ::towlower);
        return Result;
    }

}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        ::wprintf(L"usage: %s <proc.exe> <filename>\n", argv[0]);
        return 0;
    }

    DWORD Pid = proc::FindByName(argv[1]);
    if (!Pid) {
        ::wprintf(L"[!] proc not found\n");
        return 0;
    }

    ::wprintf(L"[+] found proc: %d\n", Pid);

    // kernel32!OpenProcess -> PROCESS_DUP_HANDLE for handle duplication
    HANDLE HProc = ::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!HProc) {
        ::wprintf(L"[!] OpenProcess failed: %d\n", ::GetLastError());
        return 0;
    }

    PfnNtQuerySystemInformation NtQuerySystemInformation =
    (PfnNtQuerySystemInformation)::GetProcAddress(::GetModuleHandleW(L"ntdll"), "NtQuerySystemInformation");

    PfnNtDuplicateObject NtDuplicateObject =
    (PfnNtDuplicateObject)::GetProcAddress(::GetModuleHandleW(L"ntdll"), "NtDuplicateObject");
 
    PfnNtMapViewOfSection NtMapViewOfSection =
    (PfnNtMapViewOfSection)::GetProcAddress(::GetModuleHandleW(L"ntdll"), "NtMapViewOfSection");

    ULONG BufSize = 1024 * 1024 * 2;
    std::vector<BYTE> Buf(BufSize);

    // ntdll!NtQuerySystemInformation -> SystemHandleInformation (16)
    NTSTATUS Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, Buf.data(), BufSize, &BufSize);

    if (Status == 0xC0000004) { 
        Buf.resize(BufSize + 1024);
        Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, Buf.data(), (ULONG)Buf.size(), &BufSize);
    }

    if (!NT_SUCCESS(Status)) {
        ::wprintf(L"[!] handle query failed: 0x%08X\n", Status);
        ::CloseHandle(HProc);
        return 0;
    }

    PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)Buf.data();
    ::wprintf(L"[+] enumerating %lu handles\n", HandleInfo->HandleCount);

    std::wstring SearchTerm = str::Lower(argv[2]);

    for (ULONG i = 0; i < HandleInfo->HandleCount; i++) {
        SYSTEM_HANDLE& H = HandleInfo->Handles[i];
        if (H.ProcessId != Pid)
            continue;

        HANDLE HDup = nullptr;

        if (!NT_SUCCESS(NtDuplicateObject(
            HProc,
            (HANDLE)(ULONG_PTR)H.Handle,
            ::GetCurrentProcess(),
            &HDup,
            SECTION_MAP_READ,
            0,
            0)))
            continue;

        std::wstring Type = obj::GetType(HDup);
        if (Type != L"Section") {
            ::CloseHandle(HDup);
            continue;
        }

        std::wstring FullPath = section::GetFileName(HDup);
        if (FullPath.empty()) {
            ::CloseHandle(HDup);
            continue;
        }

        const WCHAR* FileName = ::PathFindFileNameW(FullPath.c_str());
        std::wstring FileNameLower = str::Lower(FileName);

        if (FileNameLower != SearchTerm) {
            ::CloseHandle(HDup);
            continue;
        }

        ::wprintf(L"[+] found section: %s\n", FullPath.c_str());

        PVOID Base = nullptr;
        SIZE_T ViewSize = 0;

        if (NT_SUCCESS(NtMapViewOfSection(
            HDup,
            ::GetCurrentProcess(),
            &Base,
            0,
            0,
            nullptr,
            &ViewSize,
            ViewShare,
            0,
            PAGE_READONLY))) {

            HANDLE HFile = ::CreateFileW(
                L"dump.bin",
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (HFile != INVALID_HANDLE_VALUE) {
                DWORD Written;
                ::WriteFile(HFile, Base, (DWORD)ViewSize, &Written, nullptr);
                ::CloseHandle(HFile);
                ::wprintf(L"[+] dumped %llu bytes -> dump.bin\n", (ULONGLONG)ViewSize);
            }

            ::CloseHandle(HDup);
            ::CloseHandle(HProc);
            return 0;
        }

        ::CloseHandle(HDup);
    }

    ::wprintf(L"[!] section not found\n");
    ::CloseHandle(HProc);
    return 0;
}