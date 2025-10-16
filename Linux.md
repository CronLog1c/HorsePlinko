# Linux Info and SOP

**Docs / References**
- [Linux Security.pdf](https://files.catbox.moe/w2o9dk.pdf)
- [Firewall Workshop.pdf](https://files.catbox.moe/z6hgaj.pdf)
- [Red Team Debrief 2023.pdf](https://files.catbox.moe/dlldjf.pdf)


**Operating systems being used:**
> Default Creds - plinktern:IHPLRulez!

| OS / Version              | Hostname                        | IP Address       |
|---------------------------|---------------------------------|------------------|
| Linux Mint 22             | generator.team1.plinko.horse    | 172.16.1.5     | 
| **Debian 12**             | antenna.team1.plinko.horse     | 172.16.1.10     |
| **AlmaLinux 9**           | storkfront.team1.plinko.horse  | 172.16.1.20     |
| **Windows Server 2012 R2**| depot.team1.plinko.horse       | 172.16.1.30     |
| **Windows Server 2022**   | foreman.team1.plinko.horse     | 172.16.1.40     |



**Quick commands**
- `ls -la` - list all files including hidden
- `pwd` - Print Working Directory
- `tmux` - Split and detach terminals
- `sudo !!` - redo previous command as super user
- Upgrade shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'; stty raw -echo; fg; export TERM=xterm
```
- `grep -R "execute"` - Find mentions of execute recursively
- `lsof` - List Open Files (EX: `sudo lsof -p 783`)
- `ps -u <user>` (specific to a user)
- `ps -eFH` - handy ps options to include with `ps` for more detail
- `pstree -p -s PID` - tree w/ parent processes and PIDs
- `nslookup <domain-name> <dns address>` - Get resolved IP address for a DNS server 
- see DNS records (antenna) - `cat /etc/bind/db.team<t>.plinko.horse.`
- see DNS zones (antenna) - `cat /etc/bind/named.conf.default-zones`
- `ssh -i ~/.ssh/my_cool_key user@host`
- executable all files under current directory - `find . -type f -name "*.sh" -exec chmod +x {} \;`
- sudo ufw deny from 203.0.113.45

###### wheel verify
- list users in wheel group
    `getent group wheel`
- Add user to wheel group
    `sudo usermod -aG wheel username`
- Remove user from wheel group
    `sudo gpasswd -d username wheel`


##### May need to install (remember almalinux + debian)
- Git **IMPORTANT INSTALL FIRST**

##### Acquire knowledge on these
- FTP
- Postgres
- Nginx
- DNS server

---

# Prepwork

**General Process for initial hardening / routine**
1. Make backups
2. Change Passwords & Remove Users
3. Audit Sudoers
4. SSH hardening
5. Audit services/packages/cronjobs
6. Firewalls

---

**Make backups**
- Paths: `/var /etc/ /opt /home`
- Example commands:
```bash
mkdir /.backups
sudo cp -r /opt/ /.backups/opt
```
- Make immutable: `chattr +i -R /.backups`
---

**Change Passwords & Remove Users**
- `cat /etc/passwd` - normally 1000+ means a real user
- `sudo passwd {$username}` - to change individual passwd. recommend using the hash process below.
- `who -a` - show who's logged on
- `userdel {$username}` - DELETE ALL USELESS USERS!!!!

### Change password to hashed password

- Generate a new ssl hash
```
openssl passwd -6 'passwordhere'
```

- Set hash PW for plinktern
```
sudo usermod -p '$6$7ccpbuTnUM2ghnJZ$KJfEOsDRx3ghUv0kwRZlkWJaxb.8FXzJSQoi5uzdcAJYN7HoD5b3mOy.xTihL.3OG.Kn5/UrzAjQmLzOV8c1f1' plinktern
```
- Verify if it shows correctly
```
sudo getent shadow plinktern | cut -d: -f2
```
- Verify you can login with your new password
```
su - plinktern
```
### Now for jmoney too
- Set hash PW for jmoney
```
sudo usermod -p '$6$Z8uAXc3ZcuoQgVCw$.eyLXZKvmUjjsw7Uhdc3G1WoYe2ywf5o2RPL3WQYBIJfNlVl8wKlzPUrFm7bv1M888elrNxRqtnmy9QZgmrhz0' jmoney
```
- Verify if it shows correctly
```
sudo getent shadow jmoney | cut -d: -f2
```
- Verify you can login with your new password
```
su - jmoney
```


---

**Audit Sudo / privileged accounts**
- `sudo visudo` - edit/check sudoers safely
    * `cat /etc/sudoers.d/*`
    * `cat /etc/sudoers.tmp`
    * `cat /etc/group | grep sudo`
- Disabling root - edit `/etc/passwd`
```c
 root:x:0:0:root:/root:/bin/bash //change from this
 root:x:0:0:root:/root:/sbin/nologin //to this
```
###### wheel verify
- list users in wheel group
    `getent group wheel`
- Add user to wheel group
    `sudo usermod -aG wheel username`
- Remove user from wheel group
    `sudo gpasswd -d username wheel`

---

**SSH hardening / config**
- Audit and backup SSH keys in home dirs: `cd .ssh/; ls; cp authorized_keys authorized_keys2`
- Remove authorized keys if needed (figure out where our keys are and keep them authorized.):
```bash
sudo rm /root/.ssh/authorized_keys
sudo rm /home/*/.ssh/authorized_keys
```
- File: `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d`
- Suggested options:
    * `PermitRootLogin no`
    * `PermitEmptyPasswords no`
    * `PasswordAuthentication no`
    * `MaxAuthTries 3`
    * `AllowUsers user1 user2`
    * `PubkeyAuthentication yes`
    * `ClientAliveInterval 300`
    * `X11Forwarding no`
    * `AllowTcpForwarding no`
- `sudo systemctl restart ssh`
- `sudo systemctl restart sshd`

---

**Services/Packages baseline**
- List all services:
```bash
sudo systemctl list-units --all --type=service
```
- List running services:
```bash
sudo systemctl list-units --type=service --state=running
```
- Reload systemd manager configuration: `sudo systemctl daemon-reload`
- `sudo dpkg -l` (Debian-based) — list installed applications

**Cron / scheduled tasks (audit & baseline)**
- User crontabs: `crontab -e`
- System cron: `/etc/crontab`
- User cron: `/var/spool/cron/crontabs/`
- View cron.d: `ls -l /etc/cron.d`
- ls -l `/etc/cron.*`
- Monthly/weekly/daily/hourly:
```bash
ls -la /etc/cron.monthly
ls -la /etc/cron.weekly
ls -la /etc/cron.daily
ls -la /etc/cron.hourly
```
- One-liner: list all user-made cronjobs:
```bash
sudo bash -c 'for user in $(cut -f1 -d: /etc/passwd); do entries=$(crontab -u \$user -l 2>/dev/null | grep -v "^#"); if [ -n "$entries" ]; then echo "$user: Crontab entry found!"; echo "$entries"; echo; fi; done'
```
- Find cron entries in logs for user `bob`:
```bash
sudo grep cron /var/log/syslog | grep -i 'bob'
```

**Auto-start scripts locations**
- System-wide autostart script locations: `/etc/init.d/`, `/etc/rc.d/`, `/etc/systemd/system/`
- User autostart: `~/.config/autostart/` and `~/.config/`
- Autostart for all users: `ls -a /home/*/.config/autostart`

---

**Firewall baseline**
- `sudo ufw default allow outgoing`
- `sudo ufw default deny incoming`
- Allow essentials. Include any necessary for scoring as well.
	* `sudo ufw allow ssh`
	* `sudo ufw allow OpenSSH`
	* `sudo ufw allow http`
	- `sudo ufw allow https`
	* `sudo ufw allow mysql`
- `sudo ufw enable`
	- `sudo ufw status verbose`

---

# Threat Hunting / Monitoring
**Process listing**
- `sudo ps -faux` - list all running processes in tree format (pipe to `grep` to search)
	- alternative `sudo ps -eFH`
- `sudo htop` (F5 for tree view)
- `sudo pstree`
- `who -a` - Logged in users
- check `/etc/passwd` constantly and remove sus users
- `whowatch` will show a tui allowing you to monitor
- `pspy` will allow you to watch processes

**Connections / network**
- Check SSH connections:
```bash
ss -tnp | grep :22
```
- `netstat -tuln`
- `ss -tupln` or `netstat -planet` - look for weird open ports
- `lsof -i -P -n` - network connections associated with PIDs
- `osqueryi` (example query):
```sql
SELECT pid, fd, socket, local_address, remote_address, remote_port FROM process_open_sockets WHERE pid = [ANY PID];
```

**Logging / journal**
- Inspect syslog: `cat /var/log/syslog | grep <term>`
- `sudo journalctl -f -u suspicious` - follow unit logs
- Use `tail -f` on logs; `grep` for keywords as needed

**File integrity / compromised binaries**
- `sudo debsums` - checks MD5 checksums of installed files against package maintainer

**Command capture / live command monitoring**
- `sudo pspy` - Shows all commands that are executed. probably have this open always
- `sudo pspy -p` - commands shown in purple
- `sudo pspy -pf` - see all filesystem changes as well. 

**Services & units**
- `sudo systemctl list-units`
- `sudo systemctl list-units --all --type=service` 
- `sudo systemctl list-units --all --type=service --state=running`
- `sudo systemctl status suspicious.service`
- Output content of a service file: `sudo cat /etc/systemd/system/suspicious.service`
- `journalctl -f -u <unit>` for tight-following of a suspicious service
- `ls -la /etc/systemd/system`

**Cron monitoring**
- Check system cron locations and `sudo grep cron /var/log/syslog`
- Unexpected crontabs `/etc/cron.*`

**Check for webshells / weird files**
- Search web-root(s) for unusual files, php shells, base64 strings, webshell patterns (you had a placeholder; keep manual checks)

**Check editors / user artifacts**
- Text editor history files:
	* vim: `find /home/ -type f -name ".viminfo" 2>/dev/null`
	* nano: `find /home/ -type f -name ".nano_history" 2>/dev/null`
	* emacs: check `.emacs` or `.emacs.d`

**Audit log files
- `/var/log/messages` - general log for Linux systems
- `/var/log/auth.log` - authentication attempts (Debian-based)
- `/var/log/secure` - authentication attempts (RHEL/Fedora-based)
- `/var/log/utmp` - access log: users currently logged in
- `/var/log/wtmp` - access log: all users that have logged in/out
- `/var/log/kern.log` - kernel messages
- `/var/log/boot.log` - start-up messages / boot info
- `last` can show historical logins (not in original but standard; optional)

**Log tips**
- Since new events are appended to the log file, view last lines with `tail`:
```bash
tail -n 12 boot.log
```
- Search with `grep`, e.g. `grep FAILED boot.log`



---

# After Detection
**Immediate actions**
- Kill process and remove binary:
```bash
kill -9 {pid}
pkill {processName}
```
- `sudo pkill -KILL -u {targetuser}` - kill all processes for user

**Cleanup steps**
- Remove SSH keys
- Check suspicious systemd service files: `sudo cat /etc/systemd/system/suspicious.service`
- Remove suspicious cronjobs and system-wide autostarts:
	* Check `/etc/init.d/`, `/etc/rc.d/`, `/etc/systemd/system/`
	* Check `/home/*/.config/autostart`

**Post-incident: rotate credentials & review**
- Rotate passwords (`sudo passwd <user>`) and SSH keys
- Audit `/etc/passwd`, `/etc/group`, `/etc/sudoers.d/*`, and `/etc/sudoers`
- Restore from immutable backups if needed
