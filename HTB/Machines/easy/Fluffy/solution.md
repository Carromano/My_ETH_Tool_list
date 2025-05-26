# Fluffy

ip: 10.10.11.69
OS: Windows

## NOTE
As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: 
> j.fleischman / J0elTHEM4n1990!

## writeup
> https://lazyhackers.in/posts/fluffy-htb-writeup-hackthebox-season-8


# NMAP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-26 14:57 CEST
Nmap scan report for 10.10.11.69
Host is up (0.55s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-26 19:58:18Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-26T20:00:03+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-26T20:00:04+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-26T20:00:03+00:00; +7h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-26T20:00:04+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2025-05-26T19:59:26
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   379.99 ms 10.10.16.1
2   789.53 ms 10.10.11.69

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 142.35 seconds

# Exploit

1. smbclient enumeration and exploitation

> smbclient -N -L fluffy.htb

```

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT              Disk      
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to fluffy.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

> smbclient -L fluffy.htb -U j.fleischman 
> smbclient -L //10.10.11.69 -U j.fleischman 

inserisco la pass e ottengo la lista

```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT              Disk      
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to fluffy.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

> nxc smb 10.10.11.69 -u j.fleischman -d fluffy.htb -p 'J0elTHEM4n1990!' --shares

```
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
```

> nxc smb 10.10.11.69 -u j.fleischman -d fluffy.htb -p 'J0elTHEM4n1990!' --shares

```
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             [*] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE      
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share 
```

provo ad accedere a IT:

> smbclient //10.10.11.69/IT -U j.fleischman

inserendo la pass entro, ma non posso stampare nulla e non ho i permessi per fare nulla


> nxc smb 10.10.11.69 -u "j.fleischman" -p "J0elTHEM4n1990!" --rid-brute

```
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             498: FLUFFY\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.69     445    DC01             500: FLUFFY\Administrator (SidTypeUser)
SMB         10.10.11.69     445    DC01             501: FLUFFY\Guest (SidTypeUser)
SMB         10.10.11.69     445    DC01             502: FLUFFY\krbtgt (SidTypeUser)
SMB         10.10.11.69     445    DC01             512: FLUFFY\Domain Admins (SidTypeGroup)
SMB         10.10.11.69     445    DC01             513: FLUFFY\Domain Users (SidTypeGroup)
SMB         10.10.11.69     445    DC01             514: FLUFFY\Domain Guests (SidTypeGroup)
SMB         10.10.11.69     445    DC01             515: FLUFFY\Domain Computers (SidTypeGroup)
SMB         10.10.11.69     445    DC01             516: FLUFFY\Domain Controllers (SidTypeGroup)
SMB         10.10.11.69     445    DC01             517: FLUFFY\Cert Publishers (SidTypeAlias)
SMB         10.10.11.69     445    DC01             518: FLUFFY\Schema Admins (SidTypeGroup)
SMB         10.10.11.69     445    DC01             519: FLUFFY\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.69     445    DC01             520: FLUFFY\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.69     445    DC01             521: FLUFFY\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.69     445    DC01             522: FLUFFY\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.69     445    DC01             525: FLUFFY\Protected Users (SidTypeGroup)
SMB         10.10.11.69     445    DC01             526: FLUFFY\Key Admins (SidTypeGroup)
SMB         10.10.11.69     445    DC01             527: FLUFFY\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.69     445    DC01             553: FLUFFY\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.69     445    DC01             571: FLUFFY\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.69     445    DC01             572: FLUFFY\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.69     445    DC01             1000: FLUFFY\DC01$ (SidTypeUser)
SMB         10.10.11.69     445    DC01             1101: FLUFFY\DnsAdmins (SidTypeAlias)
SMB         10.10.11.69     445    DC01             1102: FLUFFY\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.69     445    DC01             1103: FLUFFY\ca_svc (SidTypeUser)
SMB         10.10.11.69     445    DC01             1104: FLUFFY\ldap_svc (SidTypeUser)
SMB         10.10.11.69     445    DC01             1601: FLUFFY\p.agila (SidTypeUser)
SMB         10.10.11.69     445    DC01             1603: FLUFFY\winrm_svc (SidTypeUser)
SMB         10.10.11.69     445    DC01             1604: FLUFFY\Service Account Managers (SidTypeGroup)
SMB         10.10.11.69     445    DC01             1605: FLUFFY\j.coffey (SidTypeUser)
SMB         10.10.11.69     445    DC01             1606: FLUFFY\j.fleischman (SidTypeUser)
SMB         10.10.11.69     445    DC01             1607: FLUFFY\Service Accounts (SidTypeGroup)
```

Quindi gli utenti che potrebbero essere interessanti sono:
- p.agila
- j.coffey



# DA FINIRE
