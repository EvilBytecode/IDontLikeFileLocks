# IDontLikeFileLocks-HandleDupliClosin

dump locked files by stealing file handles, reading them, and then deleting the lock at the source

## How It Works

instead of opening a locked file through the filesystem (which fails because sharing violations), we target the process that already has the file open.

windows represents open files as handles owned by processes. if a process has a handle to a file, the file is readable through that handle regardless of sharing flags.

we enumerate processes, find the target one, then query its handle table using NT APIs. each handle is duplicated into our own process with `NtDuplicateObject`.

once duplicated, we check:
- is this a file handle?
- does its backing filename match what we want?

if yes, we read the file directly from the duplicated handle. no filesystem open happens, so no lock checks are involved.

after extraction, we close the original handle **inside the target process** by creating a remote thread that calls `NtClose` on it. this removes the lock completely because the process no longer holds the handle.

## Why This Works 🤔

file locks exist only while handles exist.

duplicating a handle does not rerun access or sharing checks -> it just creates another reference to the same file object.

closing the remote handle simply releases that reference. once no process holds the handle anymore, the file is unlocked.

## Usage

IDontLikeFileLocks.exe chrome.exe Cookies Cookies.db

## Architecture

tested on x64 Windows 11 (25H2)

## Technical Details
- NT APIs only (ntdll)
- handle enumeration via `NtQuerySystemInformation`
- file extraction via duplicated handles
- remote handle closure via `RtlCreateUserThread`
- yes this can probs crash the process if u run it 2x 
- no i do not care, run it once and just do all ur operations in one go (wait... megamind)

## Legal

don’t use this on machines you don’t own or have permission to test on.  
prison is bad for your coding productivity 🤔❗
