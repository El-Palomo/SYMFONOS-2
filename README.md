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



