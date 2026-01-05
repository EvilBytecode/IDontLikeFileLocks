# IDontLikeFileLocks
- dump locked files / read / close remote handles :)
- Theres few methods in the repo and have readme feel free to read findfileinsection which has info on about how ive done it :D

## What This Does
Browsers lock their databases (Cookies, Login Data, History). You can't copy them while the browser is running.
This tool steals the memory-mapped section handle from the target process and dumps the file. No file I/O, no lock checks.

## Disclaimer
This technique could be (and probably is/will be) used by stealer malware to silently extract browser credentials and session tokens without killing processes or triggering obvious file access patterns. The method is effective precisely because it's quiet and non-destructive. That said, I don't encourage anyone to use this for building malware or accessing systems you don't own. This is strictly for authorized security research, red team operations with proper contracts, and forensics work where you have explicit permission. Using this on machines you're not authorized to access is illegal in basically every country US CFAA(10yrs less or more) Get it in writing, keep it legal, or don't use it at all... Thanks for reading! :)
