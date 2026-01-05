# IDontLikeFileLocks-Rstmgr

dump locked files by politely asking windows to let go of them using the official Restart Manager API.

## How It Works

normally if a file is in use, you can’t touch it. Windows has a thing called the Restart Manager (`Rstrtmgr.dll`) that apps use to safely shutdown and restart other apps while updating stuff. we abuse it just a little:

* `RmStartSession` opens a session with the OS
* `RmRegisterResources` tells it which file we want
* `RmGetList` checks if any processes are locking it
* `RmShutdown` politely tells the OS: "yo can you release this file for a hot sec?"
* `RmEndSession` closes everything back up

once the file is released, we read it and dump it into a `dump` folder. it’s basically Windows saying: "ok fine, you can have it now."

## Why This Works

because Windows has to let processes release files for updates, the Restart Manager API is allowed to temporarily unlock files
, sadly this kills the process so u can also do TASKILL /F /IM procname.exe, but this is way better cuz we dont guess the name so less IOC

## Usage

```
IDontLikeFileLocks.exe "C:\\path\\to\\locked_file"
```

it will dump the file into `dump\` in the current directory.

## Output
<img width="1114" height="338" alt="image" src="https://github.com/user-attachments/assets/e4ce8055-6dbd-40cd-b95d-0b2fadcb6968" />


## Notes

* retried 5 times if the file is stubborn
* works on normal user files (if you have permission)

## Legal

don't use this on computers you don't own or have permission to test on. messing with someone else's locked files is frowned upon and could get you into real trouble 🫰
