# NiceTryDLL
NiceTryDLL is a PoC of detecting direct syscall methods that reads NTDLL from disk. By hooking NtReadFile, it can detects both file read and file copy. For identifying the DLL, it call `NtQueryInformationFile` for getting the FileNameInformation of the file handle, and then check if the file path ends with `ntdll.dll` (or any DLL that is being blacklisted on the program). Since file read and file copy uses NtReadFile, The only way attacker can evades this is to rename the system's NTDLL to something else (which needs admin privilege).
