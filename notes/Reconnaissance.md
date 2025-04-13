# Reconnaissance

## Files

These Linux web server files are worth attempting to read by a non-root user.

### User & System Info

| File/Command                     | Purpose                          |
| -------------------------------- | -------------------------------- |
| /etc/passwd                      | List of all users (no passwords) |
| /etc/group                       | Group info, privilege mapping    |
| /etc/hostname                    | System hostname                  |
| /etc/hosts                       | Local DNS mappings               |
| /etc/os-release or /etc/*release | OS and version info              |
| /proc/version                    | Kernel version                   |
| /proc/cpuinfo / /proc/meminfo    | System specs                     |

### Home Directory Recon

| Location                                                        | What to Look For                     |
| --------------------------------------------------------------- | ------------------------------------ |
| ~/.bash_history                                                 | Command history                      |
| ~/.ssh/                                                         | id_rsa, authorized_keys, known_hosts |
| ~/.gitconfig / .git/                                            | Git info, possible URLs/tokens       |
| ~/.config/                                                      | App creds or tokens                  |
| ~/Downloads, ~/Documents, etc.                                  | Low-hanging files                    |
| `find /home -type f -name "*.txt" -o -name "*.log" 2>/dev/null` | Search home dirs for readable files  |

### Process & Network Info (via /proc)

| File/Dir            | Purpose                          |
| ------------------- | -------------------------------- |
| /proc/self/environ  | Env variables of current process |
| /proc/[pid]/cmdline | Full command line of a process   |
| /proc/net/tcp       | Open TCP sockets                 |
| /proc/[pid]/fd/     | Open file descriptors            |

### Logs

| File                                 | Info Type                         |
| ------------------------------------ | --------------------------------- |
| /var/log/syslog or /var/log/messages | System logs                       |
| /var/log/auth.log                    | Auth/sudo logs (maybe restricted) |
| /var/log/apache2/access.log          | Web server logs                   |
| /var/log/apache2/error.log           | Web server errors                 |
| /var/log/*                           | App-specific logs                 |

### Crontabs and Scheduled Tasks

| File/Command | Purpose                      |
| ------------ | ---------------------------- |
| crontab -l   | User cron jobs               |
| /etc/crontab | System-wide cron jobs        |
| /etc/cron.*  | Scheduled script directories |

### Files That Might Leak Secrets

| File/Pattern              | Why It's Useful              |
| ------------------------- | ---------------------------- |
| .env                      | Web app secrets / DB creds   |
| config.php, wp-config.php | DB/FTP creds, salts, tokens  |
| .htaccess, .htpasswd      | Web auth rules or hashes     |
| /opt/, /srv/, /var/www/   | Web server / app directories |

## Commands

## File Hunting

```bash
find / -type f \( -iname "*.conf" -o -iname "*.env" -o -iname "*.ini" -o -iname "*.log" -o -iname "*pass*" -o -iname "*secret*" -o -iname "*.bak" -o -iname "*.old" -o -iname "*.yml" -o -iname "*.json" \) -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null
```

- Includes `.ini`, `.bak`, `.old`, `.yml`, `.json`    
- Ignores noisy/protected areas like `/proc`, `/sys`, `/dev`
- Case-insensitive with `-iname`

## Interesting Files Owned by Other Users

```bash
find /home -type f -user $(whoami) -perm -u=r -exec ls -lah {} \; 2>/dev/null
```

files **not** owned by user but readable:

```bash
find /home -type f ! -user $(whoami) -perm -o=r -exec ls -lah {} \; 2>/dev/null
```

## Find SUID Binaries (for Priv Esc)

```bash
find / -perm -4000 -type f 2>/dev/null
```

These can often be abused if they're misconfigured (e.g. `nmap`, `vim`, `find`, `python` running as root).

## Look for Installed Software (to exploit)

```bash
dpkg -l 2>/dev/null | tee installed_pkgs.txt
```

You’re looking for old/outdated/known-vuln software versions.

##  List All World-Readable Files

```bash
find / -type f -perm -o=r -not -path "/proc/*" 2>/dev/null
```

## Look for Shell Histories & SSH Stuff

```bash
find /home -type f \( -name ".bash_history" -o -name ".zsh_history" -o -name "known_hosts" -o -name "authorized_keys" -o -name "id_rsa" \) 2>/dev/null
```

leaks IPs, hostnames, creds, or access tokens.

## Find Writable Files (for Persistence or Escalation)

```bash
find / -writable -type f 2>/dev/null
```

Look for modifiable config files, scripts, cron jobs

## User and Group Recon

```bash
cat /etc/passwd
cat /etc/group
groups
id
```

These tell you what accounts exist and which groups you're part of — especially look for anything like `docker`, `adm`, `sudo`, etc.


---

Last Updated 20250413