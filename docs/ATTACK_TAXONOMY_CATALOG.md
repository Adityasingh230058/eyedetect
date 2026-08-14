# 🛡️ Master EDR / XDR Cyber Attack & Threat Technique Catalog

This catalog serves as the comprehensive detection & prevention matrix for **`eyedetect`**, mapping all major attack techniques across enterprise environments.

---

## 1. Process Injection & In-Memory Attacks
* Process Hollowing (RunPE)
* Reflective DLL Injection
* Dynamic-Link Library (DLL) Side-Loading
* DLL Search-Order Hijacking
* DLL Hijacking / DLL Proxying
* Portable Executable (PE) Injection
* Thread Execution Hijacking (SetThreadContext)
* Process Doppelganging
* Process Ghosting
* Process Herpaderping
* Parent PID (PPID) Spoofing
* Access Token Theft / Impersonation
* Token Elevation / SeDebugPrivilege Abuse
* Named Pipe Impersonation
* Asynchronous Procedure Call (APC) Injection (Early Bird)
* Atom Bombing Injection
* Process Argument Spoofing

---

## 2. Credential Access & Password Theft
* Local Security Authority Subsystem Service (LSASS) Memory Dumping
* Security Account Manager (SAM) Registry Database Extraction
* Active Directory NTDS.dit Database Extraction
* Volume Shadow Copy (VSS) Credential Extraction
* LSA Secrets Registry Key Dumping (`HKLM\SECURITY\SAM`)
* Browser Saved Password Extraction (Chrome, Edge, Firefox SQLite)
* Web Session Cookie Theft (DPAPI Master Key Decryption)
* DPAPI Master Key Memory Dumping
* Keystroke Logging (Keylogging via `GetAsyncKeyState` / `SetWindowsHookEx`)
* Clipboard Data Capture & Monitoring
* Screen Capture & Video Recording
* Credential Manager Extraction (`vaultcmd.exe`)
* WiFi Pre-Shared Key (PSK) Extraction (`netsh wlan show profile`)
* SSH Private Key Extraction (`~/.ssh/id_rsa`)
* Kerberos TGS Kerberoasting (RC4 Ticket Extraction)
* Kerberos AS-REP Roasting (`DONT_REQ_PREAUTH`)
* DCSync Domain Replication Attack (`MS-DRSR` / `DsGetNcChanges`)
* DCShadow Rogue Domain Controller Registration
* Pass-the-Hash (NTLM Relay)
* Pass-the-Ticket (Kerberos TGT Injection)
* Overpass-the-Hash (Pass-the-Key)
* Kerberos Golden Ticket Forgery
* Kerberos Silver Ticket Forgery
* Kerberos Diamond / Sapphire Ticket Abuse
* Skeleton Key In-Memory Patching
* Active Directory Certificate Services (AD CS) Abuse (ESC1–ESC8)
* Multi-Factor Authentication (MFA) Fatigue & Push Bombing
* Password Spraying
* Distributed Brute-Force Authentication
* Credential Stuffing

---

## 3. Persistence & Autostart Mechanisms
* Windows Registry Run & RunOnce Keys (`HKCU` / `HKLM`)
* Windows Scheduled Tasks (`schtasks.exe` / Task Scheduler API)
* Windows Service Installation & Modification (`sc.exe` / Service Control Manager)
* Startup Folder File Placement
* WMI Event Subscription (Permanent Event Consumer)
* Component Object Model (COM) Hijacking
* Image File Execution Options (IFEO) Debugger Abuse
* AppInit_DLLs Registry Injection
* Accessibility Features Abuse (Sticky Keys `sethc.exe`, `utilman.exe`)
* Winlogon Userinit & Shell Modification
* Boot / Logon Autostart Execution
* Netsh Helper DLL Persistence
* Corrupted Shortcut (.LNK) Target Modification
* Office Add-in (XLL/VSTO) Persistence
* Linux Cron Job (`/etc/crontab`, `/etc/cron.*`)
* Linux Systemd Service Unit Installation
* Linux SSH Authorized Keys Backdoor (`~/.ssh/authorized_keys`)
* Linux Shell Profile Injection (`.bashrc`, `.bash_profile`, `/etc/profile`)
* Linux SUID / SGID Binary Creation (`chmod +s`)
* Web Shell Persistence (IIS `w3wp.exe`, Apache, Nginx, Tomcat)
* Browser Extension Persistence

---

## 4. Privilege Escalation
* User Account Control (UAC) Bypass via Fodhelper
* UAC Bypass via Eventvwr / Slui / ComputerDefaults
* Windows Print Spooler Exploitation (PrintNightmare)
* Unquoted Service Path Exploitation
* Weak Service Permissions Exploitation
* DLL Search Order Hijacking for Privilege Escalation
* Windows Kernel Privilege Escalation
* Linux SUID Binary Abuse (GTFOBins)
* Linux Sudoers Misconfiguration / Sudo Abuse
* Linux Kernel Local Privilege Escalation (Dirty COW, Dirty Pipe)
* Container Breakout / Escape to Host

---

## 5. Defense Evasion & Anti-Forensics
* Windows Event Log Clearing (`wevtutil.exe cl`)
* Windows Defender Real-Time Protection Disabled (`Set-MpPreference -DisableRealtimeMonitoring`)
* Windows Defender / Antivirus Exclusion Abuse (`Add-MpPreference -ExclusionPath`)
* Forensic Timestomping (File Timestamp Modification)
* File & Log Shredding / Deletion (`srm`, `cipher /w`, `sdelete`)
* High-Entropy Payload Obfuscation & Encoding
* Multi-Layer Base64 / Hex / XOR Deobfuscation
* Inline PowerShell Command Obfuscation (Tick marks, format strings)
* Living-off-the-Land Binaries and Scripts (LOLBAS: `certutil`, `bitsadmin`, `mshta`, `rundll32`, `regsvr32`)
* Process Masquerading & Fake Executable Names (`svchost.exe`, `lsass.exe`)
* Binary Padding (Inflating file size with null bytes)
* Signed Binary Proxy Execution
* EDR / Antivirus Hook Unhooking (Direct System Calls / Syscalls)
* Process Suspension / Thread Freezing

---

## 6. Lateral Movement & Internal Pivoting
* Remote Windows Management Instrumentation (WMI / `wmic process call create`)
* Remote PowerShell (WinRM / `Enter-PSSession` / `Invoke-Command`)
* Remote Service Creation via SMB (`sc.exe \\target create`)
* Remote Desktop Protocol (RDP) Lateral Pivoting (`mstsc.exe /v:`)
* Secure Shell (SSH) Pivoting & Port Forwarding (`ssh -L`, `plink.exe`)
* PsExec Service Installation & Remote Execution
* NTLM Relay & SMB Relay Attacks
* LLMNR / NBT-NS / mDNS Poisoning (Responder)
* Internal Port Scanning & Subnet Sweeping
* Active Directory Reconnaissance & BloodHound Enumeration

---

## 7. Command & Control (C2) & Network Threats
* Periodic Automated C2 Beaconing (Heartbeat Interval with Low Jitter)
* Algorithmic Domain Generation (DGA) C2 Channels
* DNS Tunneling & Covert Query Encoding
* HTTP / HTTPS C2 Communication
* Covert ICMP Ping Tunneling
* WebSockets / gRPC C2 Communication
* Domain Fronting / CDN Proxying
* Cloud Storage / Web Service C2 (Discord, Telegram, GitHub API)
* ARP Cache Poisoning & Man-in-the-Middle (MITM)
* DHCP Starvation & Rogue DHCP Server
* TCP SYN Flood Denial of Service
* TCP Reset Attack & Session Hijacking
* Port Scanning (Horizontal Subnet Sweep & Vertical Port Scan)

---

## 8. Data Exfiltration & Theft
* Data Staging & Password-Protected Archiving (`7z.exe`, `rar.exe`, `tar`)
* Cloud Storage CLI Upload (AWS CLI `s3 cp`, `rclone`, `azcopy`, `gsutil`, `mega-cmd`)
* Exfiltration Over Web Service (HTTP/S POST to External C2)
* Exfiltration Over DNS Queries (Base64/Hex DNS TXT/A Records)
* Exfiltration Over ICMP Payloads
* Exfiltration to Removable Media (USB Mass Storage Drive)
* Screen Capture / Screenshot Staging
* Browser Data & History Harvesting

---

## 9. Web Application & API Vulnerabilities (OWASP Top 10)
* SQL Injection (UNION-based, Blind Boolean, Time-based Sleep, Error-based)
* NoSQL Injection (MongoDB query manipulation)
* Cross-Site Scripting (Reflected XSS, Stored XSS, DOM-based XSS)
* Server-Side Request Forgery (SSRF - querying `169.254.169.254` Cloud Metadata)
* Path Traversal / Local File Inclusion (LFI - `/etc/passwd`, `win.ini`)
* Remote File Inclusion (RFI)
* OS Command Injection
* Server-Side Template Injection (SSTI)
* Cross-Site Request Forgery (CSRF)
* Broken Object-Level Authorization (BOLA / IDOR)
* Broken Function-Level Authorization (BFLA)
* GraphQL Introspection & Schema Enumeration
* GraphQL Denial of Service (Deep Nested Query)
* JWT Manipulation (None Algorithm, Secret Confusion)
* Unrestricted File Upload (Uploading `.php`, `.jsp`, `.exe`)
* HTTP Request Smuggling

---

## 10. Multi-Cloud & Workload Security (AWS / GCP / Azure / Kubernetes)
* Cloud IAM Backdoor Access Key Creation (`CreateAccessKey`)
* Cloud IAM Privilege Escalation (`AttachUserPolicy` -> `AdministratorAccess`)
* Cloud Storage Bucket Public Exposure (S3 / GCS `public-read`, `allUsers`)
* Instance Metadata Service (IMDSv1) Token Theft
* Kubernetes Privileged Container Escape (`privileged: true`)
* Kubernetes Host Filesystem Mount Abuse (`/var/run/docker.sock`, `/host`)
* Kubernetes Cluster Admin RoleBinding Abuse
* Serverless Function Code Tampering
* Cloud Temporary Security Token (STS) Theft

---

## 11. Malware Family Classifications
* Ransomware (Mass File Encryption, Volume Shadow Copy Deletion)
* Wiper Malware (Raw Sector MBR/VBR Overwrite, Disk Formatting)
* Infostealers (RedLine, Racoon, Vidar, AgentTesla)
* Remote Access Trojans (RATs: AsyncRAT, Cobalt Strike, QuasarRAT)
* Cryptominers (XMRig, ccminer, High-CPU Mining Pools)
* Banking Trojans (TrickBot, Emotet, QakBot)
* Web Shells (China Chopper, Behinder, Godzilla, C99)
* Dual-Extension Executable Droppers (`invoice.pdf.exe`)
* Living-off-the-Land Malicious Downloaders (`certutil -urlcache`)
