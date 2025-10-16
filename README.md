# Horse Plink Scripts

**A small collection of PowerShell scripts that was used at Hack@UCF IHPL.**  
---

## Overview

- **`Reset-AllPasswords.ps1`**  
  Randomizes and sets new passwords for all local users. Posts the new plaintext credentials to a Discord webhook for audit.

- **`User-Audit-And-Remove.ps1`**  
  Enumerates local users, collects profile info, sends an audit report to a Discord webhook, and optionally removes selected accounts and profile folders.

- **`Watchdog-Monitor.ps1`**  
  Continuously monitors configured services, firewall profiles/rules, key ports (RDP/SSH/etc.), and logon events. Sends alerts to a Discord webhook and attempts basic remediation. #This one semi worked. It would let you know if rules were changed in the firewall everything else was a little buggy.

---
```powershell command
powershell -ExecutionPolicy Bypass -File .\Reset-AllPasswords.ps1 .\User-Audit-And-Remove.ps1 .\Watchdog-Monitor.ps1
