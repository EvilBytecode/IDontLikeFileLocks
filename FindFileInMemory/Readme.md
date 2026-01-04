# IDontLikeFileLocks

dump locked files by reading them from process memory instead of dealing with filesystem bullshit

## How It Works

basically if a file is locked you just read it from the process that has it open lol. 

we use VirtualQueryEx to walk through all the memory in the target process and look for MEM_MAPPED regions with PAGE_READONLY protection because that's how memory mapped files work. GetMappedFileNameW tells us what file each memory region is actually backing. once we find the file we want we just ReadProcessMemory and copy the whole thing into our own process where it's unlocked and we can do whatever.

for chrome cookies it's slightly annoying because the Cookies database isn't in the main chrome.exe process, it's in some random subprocess called "Network Service" that chrome spawns. so we walk all the child processes, read their command line args from the PEB, and look for `--type=utility --utility-sub-type=network.mojom.NetworkService` which is how you identify it. then we dump from that process instead.

once we have the memory buffer we try writing to temp directory first and if that fails we just dump it in the current directory. either way the file is unlocked in our memory so we can write it wherever.

## Why This Works
cuz chrome maps its sqlite databases read-only into memory so they're just chilling there ready to be copied.

## Usage

```
IDontLikeFileLocks.exe chrome.exe Cookies dump.db
IDontLikeFileLocks.exe brave.exe "Login Data" passwords.db
IDontLikeFileLocks.exe msedge.exe Cookies --debug
```

the `--debug` flag dumps all memory mapped files in the process which is useful when you're exploring what's available or forgot the exact filename

## Output
<img width="1095" height="186" alt="image" src="https://github.com/user-attachments/assets/e750a471-b3f8-428a-a527-c74e9c066dd6" />


## Architecture 

tested on x64 25H2 Win11 (26200.7462)

## Technical Details
- new/delete for memory management because malloc is for C programmers
- the chrome network service detection is just string matching on command line args. not elegant but it works and i'm lazy.

## Legal

don't use this on computers you don't own or have permission to test on. federal prison sucks and you can't shitpost from there.

## 
