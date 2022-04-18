# NiceTryDLL
NiceTryDLL is a PoC of detecting direct syscall methods that reads NTDLL from disk. By hooking NtReadFile, it can detects both file read and file copy. For identifying the DLL, it call `NtQueryInformationFile` for getting the FileNameInformation of the file handle, and then check if the file path ends with `ntdll.dll`. Since file read and file copy uses NtReadFile, The only way attacker can evades this is to rename the system's NTDLL to something else or hook `NtQueryInformationFile` to spoof the filename. Again, this is just a PoC, you can add more checks to validate if the DLL is NTDLL if you want to.

# Demonstration
### File read
![File read](https://user-images.githubusercontent.com/41237415/163882528-6d8adcbe-447d-4f92-96c0-4e7bd9b38744.png)
### File copy
![File copy](https://user-images.githubusercontent.com/41237415/163882595-e49c24f8-4de8-49d5-9815-621b99e81227.png)

