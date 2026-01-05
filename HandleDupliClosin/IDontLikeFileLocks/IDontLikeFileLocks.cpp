#pragma once

#include<windows.h>
#include<winternl.h>
#include<string>
#include<vector>
#include<map>
#include<cstdio>
// i recommend making one hpp and just make this into plug n play. thecode is very messy but it works...
namespace IDontLikeFileLocks {

    struct SYSTEM_HANDLE_ENTRY {
        HANDLE Handle;
        ULONG_PTR ObjectPointerCount;
        ULONG_PTR HandleReferenceCount;
        ULONG GrantedAccess;
        ULONG ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };

    struct SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_ENTRY Handles[1];
    };

    struct OBJECT_TYPE_INFORMATION {
        UNICODE_STRING TypeName;
        ULONG TotalNumberOfObjects;
        ULONG TotalNumberOfHandles;
    };

    struct SYSTEM_PROCESS_INFORMATION {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        BYTE Reserved1[48];
        UNICODE_STRING ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        PVOID Reserved2;
        ULONG HandleCount;
        ULONG SessionId;
        PVOID Reserved3;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG Reserved4;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        PVOID Reserved5;
        SIZE_T QuotaPagedPoolUsage;
        PVOID Reserved6;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER Reserved7[6];
    };

    struct FILE_STANDARD_INFO {
        LARGE_INTEGER AllocationSize;
        LARGE_INTEGER EndOfFile;
        ULONG NumberOfLinks;
        BOOLEAN DeletePending;
        BOOLEAN Directory;
    };

    struct FILE_POSITION_INFO {
        LARGE_INTEGER CurrentByteOffset;
    };

    struct FILE_NAME_INFO {
        ULONG FileNameLength;
        WCHAR FileName[1];
    };

    using NtQuerySystemInformation = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    using NtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtQueryObject = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using NtClose = NTSTATUS(NTAPI*)(HANDLE);
    using NtReadFile = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    using NtQueryInformationFile = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
    using NtSetInformationFile = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
    using NtDuplicateObject = NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
    using NtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID);
    using NtCreateFile = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    using NtWriteFile = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    using RtlCreateUserThread = NTSTATUS(NTAPI*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);
    using RtlGetCurrentDirectory_U = ULONG(NTAPI*)(ULONG, PWSTR);

    namespace nt {

        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");

        NtQuerySystemInformation QuerySystemInformation = (NtQuerySystemInformation)::GetProcAddress(ntdll, "NtQuerySystemInformation");
        NtQueryInformationProcess QueryInformationProcess = (NtQueryInformationProcess)::GetProcAddress(ntdll, "NtQueryInformationProcess");
        NtQueryObject QueryObject = (NtQueryObject)::GetProcAddress(ntdll, "NtQueryObject");
        NtClose Close = (NtClose)::GetProcAddress(ntdll, "NtClose");
        NtReadFile ReadFile = (NtReadFile)::GetProcAddress(ntdll, "NtReadFile");
        NtQueryInformationFile QueryInformationFile = (NtQueryInformationFile)::GetProcAddress(ntdll, "NtQueryInformationFile");
        NtSetInformationFile SetInformationFile = (NtSetInformationFile)::GetProcAddress(ntdll, "NtSetInformationFile");
        NtDuplicateObject DuplicateObject = (NtDuplicateObject)::GetProcAddress(ntdll, "NtDuplicateObject");
        NtOpenProcess OpenProcess = (NtOpenProcess)::GetProcAddress(ntdll, "NtOpenProcess");
        NtCreateFile CreateFile = (NtCreateFile)::GetProcAddress(ntdll, "NtCreateFile");
        NtWriteFile WriteFile = (NtWriteFile)::GetProcAddress(ntdll, "NtWriteFile");
        RtlCreateUserThread CreateUserThread = (RtlCreateUserThread)::GetProcAddress(ntdll, "RtlCreateUserThread");
        RtlGetCurrentDirectory_U GetCurrentDirectory = (RtlGetCurrentDirectory_U)::GetProcAddress(ntdll, "RtlGetCurrentDirectory_U");

    }

    std::map<DWORD, std::vector<SYSTEM_HANDLE_ENTRY>> ScanProcesses(const std::wstring& target) {
        std::map<DWORD, std::vector<SYSTEM_HANDLE_ENTRY>> result;

        ULONG bufsize = 1024 * 1024;
        std::vector<BYTE> buf;
        NTSTATUS status = 0xC0000004;

        while (status == 0xC0000004) {
            buf.resize(bufsize);
            status = nt::QuerySystemInformation(5, buf.data(), bufsize, &bufsize);
        }

        if (status != 0) {
            return result;
        }

        ULONG offset = 0;
        while (offset < buf.size()) {
            auto* info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buf.data() + offset);

            if (info->UniqueProcessId && info->ImageName.Buffer) {
                std::wstring name(info->ImageName.Buffer, info->ImageName.Length / sizeof(WCHAR));

                if (_wcsicmp(name.c_str(), target.c_str()) == 0) {
                    DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(info->UniqueProcessId));

                    CLIENT_ID cid{};
                    cid.UniqueProcess = info->UniqueProcessId;

                    OBJECT_ATTRIBUTES oa{};
                    oa.Length = sizeof(OBJECT_ATTRIBUTES);

                    HANDLE hproc = nullptr;

                    if (nt::OpenProcess(&hproc, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, &oa, &cid) == 0) {
                        ULONG hbufsize = 0;
                        std::vector<BYTE> hbuf;
                        NTSTATUS hstatus = 0xC0000004;

                        while (hstatus == 0xC0000004) {
                            if (hbufsize > 0) {
                                hbuf.resize(hbufsize);
                            }
                            hstatus = nt::QueryInformationProcess(hproc, 51, hbufsize > 0 ? hbuf.data() : nullptr, hbufsize, &hbufsize);
                        }

                        if (hstatus == 0 && hbufsize >= sizeof(SYSTEM_HANDLE_INFORMATION_EX)) {
                            auto* hinfo = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(hbuf.data());
                            ULONG_PTR count = hinfo->NumberOfHandles;

                            if (count > 0) {
                                size_t expected = sizeof(SYSTEM_HANDLE_INFORMATION_EX) + (count - 1) * sizeof(SYSTEM_HANDLE_ENTRY);

                                if (hbufsize >= expected) {
                                    std::vector<SYSTEM_HANDLE_ENTRY> handles;
                                    handles.assign(hinfo->Handles, hinfo->Handles + count);
                                    result[pid] = std::move(handles);
                                }
                            }
                        }

                        nt::Close(hproc);
                    }
                }
            }

            if (info->NextEntryOffset == 0) {
                break;
            }
            offset += info->NextEntryOffset;
        }

        return result;
    }

    struct ExtractResult {
        std::vector<BYTE> data;
        std::wstring path;
        bool success = false;
        std::wstring error;
    };

    ExtractResult ExtractFileFromHandle(HANDLE handle, DWORD owner, const std::wstring& pattern) {
        ExtractResult result;

        CLIENT_ID cid{};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(owner));

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(OBJECT_ATTRIBUTES);

        HANDLE hproc = nullptr;
        if (nt::OpenProcess(&hproc, PROCESS_DUP_HANDLE, &oa, &cid) != 0) {
            result.error = L"Failed to open process";
            return result;
        }

        HANDLE hdup = nullptr;
        HANDLE hcur = reinterpret_cast<HANDLE>(-1);
        ULONG access = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
            FILE_READ_EA | FILE_WRITE_EA | FILE_READ_ATTRIBUTES |
            FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

        if (nt::DuplicateObject(hproc, handle, hcur, &hdup, access, 0, 0) != 0) {
            nt::Close(hproc);
            result.error = L"Failed to duplicate handle";
            return result;
        }

        ULONG tbufsize = 0;
        std::vector<BYTE> tbuf;
        NTSTATUS status = 0xC0000004;

        while (status == 0xC0000004) {
            if (tbufsize > 0) {
                tbuf.resize(tbufsize);
            }
            status = nt::QueryObject(hdup, 2, tbufsize > 0 ? tbuf.data() : nullptr, tbufsize, &tbufsize);
        }

        if (status != 0) {
            nt::Close(hdup);
            nt::Close(hproc);
            result.error = L"Failed to query object type";
            return result;
        }

        auto* tinfo = reinterpret_cast<OBJECT_TYPE_INFORMATION*>(tbuf.data());
        if (!tinfo->TypeName.Buffer) {
            nt::Close(hdup);
            nt::Close(hproc);
            result.error = L"No type name";
            return result;
        }

        std::wstring tname(tinfo->TypeName.Buffer, tinfo->TypeName.Length / sizeof(WCHAR));
        if (tname != L"File") {
            nt::Close(hdup);
            nt::Close(hproc);
            result.error = L"Not a file handle";
            return result;
        }

        ULONG nbufsize = 4096;
        std::vector<BYTE> nbuf(nbufsize);
        IO_STATUS_BLOCK iosb{};

        if (nt::QueryInformationFile(hdup, &iosb, nbuf.data(), nbufsize, 9) != 0) {
            nt::Close(hdup);
            nt::Close(hproc);
            result.error = L"Failed to query file name";
            return result;
        }

        auto* ninfo = reinterpret_cast<FILE_NAME_INFO*>(nbuf.data());
        ULONG nlen = ninfo->FileNameLength / sizeof(WCHAR);

        if (nlen > 0) {
            std::wstring fullpath(ninfo->FileName, nlen);

            size_t sep = fullpath.rfind(L'\\');
            if (sep == std::wstring::npos) {
                sep = fullpath.rfind(L'/');
            }

            std::wstring filename = (sep == std::wstring::npos) ? fullpath : fullpath.substr(sep + 1);

            if (_wcsicmp(filename.c_str(), pattern.c_str()) != 0) {
                nt::Close(hdup);
                nt::Close(hproc);
                result.error = L"File name does not match pattern";
                return result;
            }

            FILE_STANDARD_INFO sinfo{};
            iosb = {};

            if (nt::QueryInformationFile(hdup, &iosb, &sinfo, sizeof(sinfo), 5) != 0) {
                nt::Close(hdup);
                nt::Close(hproc);
                result.error = L"Failed to query file size";
                result.path = fullpath;
                return result;
            }

            LONGLONG fsz = sinfo.EndOfFile.QuadPart;
            if (fsz == 0) {
                result.path = fullpath;
                result.success = true;
                nt::Close(hdup);
                nt::Close(hproc);
                return result;
            }

            FILE_POSITION_INFO pinfo{};
            pinfo.CurrentByteOffset.QuadPart = 0;
            nt::SetInformationFile(hdup, &iosb, &pinfo, sizeof(pinfo), 14);

            result.data.resize(static_cast<size_t>(fsz));
            iosb = {};

            if (nt::ReadFile(hdup, nullptr, nullptr, nullptr, &iosb, result.data.data(), static_cast<ULONG>(fsz), nullptr, nullptr) != 0) {
                nt::Close(hdup);
                nt::Close(hproc);
                result.error = L"Failed to read file";
                result.path = fullpath;
                return result;
            }

            result.data.resize(static_cast<size_t>(iosb.Information));
            result.path = fullpath;
            result.success = true;
        }
        else {
            result.error = L"Empty file name";
        }

        nt::Close(hdup);
        nt::Close(hproc);
        return result;
    }

    bool WriteFileToDisk(const std::vector<BYTE>& content, const std::wstring& dest) {
        std::wstring path;

        if (dest.length() >= 2 && dest[1] == L':') {
            path = dest;
        }
        else {
            WCHAR cwd[MAX_PATH]{};
            ULONG len = nt::GetCurrentDirectory(sizeof(cwd), cwd);
            if (len == 0) {
                return false;
            }
            path = std::wstring(cwd) + L"\\" + dest;
        }

        path = L"\\??\\" + path;

        UNICODE_STRING us{};
        us.Length = static_cast<USHORT>(path.length() * sizeof(WCHAR));
        us.MaximumLength = us.Length + sizeof(WCHAR);
        us.Buffer = const_cast<PWSTR>(path.c_str());

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(OBJECT_ATTRIBUTES);
        oa.ObjectName = &us;
        oa.Attributes = OBJ_CASE_INSENSITIVE;

        IO_STATUS_BLOCK iosb{};
        HANDLE hfile = nullptr;

        NTSTATUS status = nt::CreateFile(&hfile, FILE_WRITE_DATA | FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb,
            nullptr, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

        if (status != 0) {
            return false;
        }

        iosb = {};
        status = nt::WriteFile(hfile, nullptr, nullptr, nullptr, &iosb,
            const_cast<PVOID>(static_cast<const void*>(content.data())), static_cast<ULONG>(content.size()), nullptr, nullptr);

        nt::Close(hfile);
        return status == 0;
    }

    bool CloseRemoteHandle(DWORD owner, HANDLE handle) {
        CLIENT_ID cid{};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(owner));

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(OBJECT_ATTRIBUTES);

        HANDLE hproc = nullptr;
        ULONG access = PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD;

        if (nt::OpenProcess(&hproc, access, &oa, &cid) != 0) {
            return false;
        }

        PVOID addr = reinterpret_cast<PVOID>(nt::Close);
        HANDLE hthread = nullptr;

        NTSTATUS status = nt::CreateUserThread(hproc, nullptr, FALSE, 0, 0, 0, addr, handle, &hthread, nullptr);

        if (hthread) {
            nt::Close(hthread);
        }
        nt::Close(hproc);

        return status == 0;
    }

}

int wmain(int argc, wchar_t** argv) {

    if (argc < 4) {
        wprintf(L"usage: flock.exe <process.exe> <filename> <output>\n");
        return 0;
    }

    const wchar_t* targetProcess = argv[1];
    const wchar_t* targetFile = argv[2];
    const wchar_t* outputPath = argv[3];

    auto processes = IDontLikeFileLocks::ScanProcesses(targetProcess);

    if (processes.empty()) {
        wprintf(L"[!] no matching process found\n");
        return 0;
    }

    for (auto& it : processes) {
        DWORD pid = it.first;
        auto& handles = it.second;

        wprintf(L"[+] pid %lu (%zu handles)\n", pid, handles.size());

        for (auto& h : handles) {
            IDontLikeFileLocks::CloseRemoteHandle(pid, h.Handle);

            auto res = IDontLikeFileLocks::ExtractFileFromHandle(
                h.Handle,
                pid,
                targetFile
            );

            if (!res.success) {
                continue;
            }

            wprintf(L"[+] extracted: %ls\n", res.path.c_str());

            if (!IDontLikeFileLocks::WriteFileToDisk(res.data, outputPath)) {
                wprintf(L"[!] failed to write output file\n");
                return 0;
            }

            wprintf(L"[+] saved to: %ls\n", outputPath);


            return 0;
        }
    }

    wprintf(L"[!] no matching file handle found\n");
    return 0;
}