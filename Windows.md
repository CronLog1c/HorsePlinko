# Windows Defense SOP and Info

[Intro to Windows Server.pdf](https://files.catbox.moe/6g3pkb.pdf)
[Windows Workshop.pdf](https://files.catbox.moe/pqr4vi.pdf)
[Windows Security GBM.pdf](https://files.catbox.moe/dqzl53.pdf)


| OS / Version              | Hostname                        | IP Address       |
|---------------------------|---------------------------------|------------------|
| Linux Mint 22             | generator.team1.plinko.horse    | 172.16.1.5     | 
| **Debian 12**             | antenna.team1.plinko.horse     | 172.16.1.10     |
| **AlmaLinux 9**           | storkfront.team1.plinko.horse  | 172.16.1.20     |
| **Windows Server 2012 R2**| depot.team1.plinko.horse       | 172.16.1.30     |
| **Windows Server 2022**   | foreman.team1.plinko.horse     | 172.16.1.40     |


# Info
Ports:
- 21 - FTP **red team hinted at using this in some way**
- 3389 TCP - Remote Desktop Protocol (RDP)
- 53 TCP/UDP - DNS
- 88 TCP/UDP - Active directory / Kerberos
- more probably
# Prepwork
- Rotate Passwords
- Setup Auditing
	- Process Monitor - Logs everything
	- secpol.msc - audit logon attempts
- gpedit.msc
	- [DoD GPO Policies](https://public.cyber.mil/stigs/gpo/)
		- Account Policy GPO
		- Local Policies/Security Options GPO
		    - **User Rights Assignment:** Limits which accounts can perform specific actions (e.g., "log on as a service," "access this computer from the network").
		    - **Audit Policy:** Ensures that the critical Event IDs (like 4624, 4625, and 4688) are being logged.
		- Windows Firewall GPO
		- User Rights Assignment and Privileged Accounts

# Monitoring
- Google / chatgpt unfamiliar names of processes
#### Tools:
- Process Explorer - Better task manager
- System Informer - Better Process Explorer
- Autoruns
- TCPView - Monitor ingoing/outgoing connections
	- Useful for finding beacons
#### Event IDs
##### Users
4624 - Successful Logon
4625 - Failed Logon
4648 - Explicit Credentials Logon
4720 - User account created
4726 - User deleted
4732/4738/4756 - Member added to group
4672 - Special privileges assigned
##### Processes
4697 - Installed service
4688 - New process created
4698 - scheduled task created
##### Other
1102 - Audit log cleared
4719 - Audit policy changed

# After detection
- reset passwords
- check firewall
- lusrmgr.msc


# Categorize : 

Disable not used network drivers


Disable SMB protocol

SMB is a file-sharing protocol exploited by hackers in the wild. The protocol is primarily used for file sharing in a network; therefore, you must disable the protocol if your computer is not part of a network by issuing the following command in PowerShell.

 Administrator - Windows PowerShell
           user@machine$ Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Path          :
Online        : True
RestartNeeded : False
        


Setting A Lockout Policy

To protect your system password from being guessed by an attacker, we can set out a lockout policy so the account will automatically lock after certain invalid attempts. To set a lockout policy, go to Local Security Policy > Windows Settings > Account Policies > Account Lockout Policy and configure values to lock out hackers after three invalid attempts.

netstat -abno





--- 
> taken from https://github.com/cscohera/HPS/blob/main/More_info/Windows.md

Security policies: Make sure to back up GPOS and re run gpo script
Remove change password
Rename administrator
Prohibit access to control panel
Prevent access to the command prompt
Deny all removable storage access
Prohibit users from installing unwanted software
Reinforce guest account status settings
Do not store LAN manager hash values on next password changes
Audit directory service access and audit directory service changes

Reenabling Windows defender

Re-enable Real-Time Protection via PowerShell:
PowerShell

Set-MpPreference -DisableRealtimeMonitoring 0

or

Fix Registry Keys:

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 0

Or

Restart the Service:


Critical Defensive Strategies
CHANGE ALL PASSWORDS IMMEDIATELY!
Uninstall unnecessary programs 
Disable bluetooth and beacons
Lugsar change passwords via script
 Scheduled Tasks:
Check for any task scheduled in schtasks.exe or GUI

Startup Folders & Registry:
	HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run and the equivalent HKEY_LOCAL_MACHINE key.

Check Services

Remove a service: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-service?view=powershell-7.5


Put lgpo in folder with policies name 1 and 2
Then cd file path
LGPO.exe /g 1
Do with all other important policys
Do dod in both windows fire wall and gpedit.msc

Task Manager

Re enable task manager:  REG add  HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 0 /f



Firewall

Re-enable all firewall profiles (Domain, Private, Public):
netsh advfirewall set allprofiles state on
Or
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True


If they cook us and do not have ability to Re-enable firewall we will use
Cmd admin and remove quotes:
route ADD “Attacker IP” MASK 255.255.255.255 127.0.0.1
Or use -p with command so it is persistent if pc restarted
route -p ADD “Attacker IP” MASK 255.255.255.255 127.0.0.1
Check route is in place with “route print” and use 
route DELETE “ip”
If needed



Turn the firewall on or off
Go to Settings > Windows Security > Firewall & network protection and select On or Off. 
Configure a specific port
Go to Windows Defender Firewall, click Inbound Rules, then New Rule. Select the port, enter the port number, and choose to allow or block the connection. 
Configure outbound connections
Repeat the steps for configuring a specific port, but select Outbound Rules instead of Inbound Rules. 
Reset the firewall
Go to Control Panel > System and Security > Windows Defender Firewall and click Restore Defaults. 


Device security/ memory integrity/ turn on

App and browser control/ force randomization for images/ on by default

Autoplay off

Config User Account Control to limit privileges
Implement fire wall rules

Seeing connections to the server that may need to be blocked
See remotely connected computers: Scan with netstat -ba its goated or using netstat -ano
Block ips via cmd: netsh advfirewall firewall add rule name="Block IP" dir=out action=block remoteip=IP
https://superuser.com/questions/1040874/how-to-prevent-remote-connections-from-another-machine

Use: netstat -a for ports
Local security policy
Lockout policy
Account lockout duration 15 mins
Account lockout threshold: 10 failed authentication attempts
Reset counter after: 15 mins

Windows defender antivirus:
Turn off windows defender antivirus: disabled


 Enumerate users and groups
        Change passwords for any service accounts
        Back up critical services
        Download tools
        Patch Windows and Critical service
        Disable unneeded software and services
        Check for Backdoors using TCP Viewer, Process Explorer, Autoruns, Everything

               
    Change passwords for any service accounts
        Varies by service on what to do

    Backup Critical Services
        Varies by service on what to do, but most of the time just copy the files to a folder and zip it somewhere people wouldn’t look.


    Patch Windows and Critical services
        Check the patch checklist for specific process to patch OS and services

    Disable unneeded software and services

    Check for Backdoors using TCP Viewer, Process Explorer, Autoruns, Everything
        Don’t just kill anything because the scoring engine may need it but do research and view logs
        Usually sort by publisher (look for not verified, but some apps are just not)
        For Everything sort by last modified



Add Script block logging for powershell

Snort:

https://github.com/thereisnotime/Snort-Default-Windows-Configuration

https://medium.com/linode-cube/5-essential-steps-to-hardening-your-mysql-database-591e477bbbd7

