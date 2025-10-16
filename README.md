# PowerShell Scripts

**A small collection of PowerShell scripts used during Hack@UCF IHPL.**

---

## Overview

### `Reset-AllPasswords.ps1`  
Randomizes and sets new passwords for all local user accounts.  
Posts plaintext credentials to a configured Discord webhook for auditing purposes.

---

### `User-Audit-And-Remove.ps1`  
- Enumerates all local user accounts  
- Collects profile data  
- Sends a detailed audit report to a Discord webhook  
- Optionally removes selected user accounts and profile folders

---

### `Watchdog-Monitor.ps1`  
Continuously monitors the following:  
- Selected services  
- Firewall profiles and rules  
- Key ports (e.g., RDP, SSH)  
- Logon events  

Sends alerts to a Discord webhook and attempts basic remediation when issues are detected.  

Note: Firewall rule detection is reliable, but other components may behave inconsistently.

---

## Usage

```powershell
powershell -ExecutionPolicy Bypass -File .\Reset-AllPasswords.ps1
powershell -ExecutionPolicy Bypass -File .\User-Audit-And-Remove.ps1
powershell -ExecutionPolicy Bypass -File .\Watchdog-Monitor.ps1

---

# Learning
https://github.com/mubix/howtowinccdc
https://docs.google.com/document/d/13Ozs8XY0mEgFQ3cnbVhd5RV3OmBXIBuZMLhPSGonsuE/edit?tab=t.0#heading=h.gjojmcvrvz18
https://cypat.guide/
