# Escape Two

ip: 10.10.11.51

## descrizione macchina

"as in real life windows pentesting, you will start this machine with these credentials"

rose
KxEPkKe6R8su

# NMAP

### Prima scan
  
Nmap scan report for 10.10.11.51  
Host is up (0.31s latency).  
Not shown: 987 filtered tcp ports (no-response)  
PORT     STATE SERVICE       VERSION  
53/tcp   open  domain        Simple DNS Plus  
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-24 12:27:12Z)  
135/tcp  open  msrpc         Microsoft Windows RPC  
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
| ssl-cert: Subject: commonName=DC01.sequel.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb  
| Not valid before: 2024-06-08T17:35:00  
|_Not valid after:  2025-06-08T17:35:00  
|_ssl-date: 2025-03-24T12:28:58+00:00; 0s from scanner time.  
445/tcp  open  microsoft-ds?  
464/tcp  open  kpasswd5?  
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
|_ssl-date: 2025-03-24T12:28:59+00:00; +1s from scanner time.  
| ssl-cert: Subject: commonName=DC01.sequel.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb  
| Not valid before: 2024-06-08T17:35:00  
|_Not valid after:  2025-06-08T17:35:00  
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM  
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback  
| Not valid before: 2025-03-24T10:03:01  
|_Not valid after:  2055-03-24T10:03:01  
| ms-sql-info:   
|   10.10.11.51:1433:   
|     Version:   
|       name: Microsoft SQL Server 2019 RTM  
|       number: 15.00.2000.00  
|       Product: Microsoft SQL Server 2019  
|       Service pack level: RTM  
|       Post-SP patches applied: false  
|_    TCP port: 1433  
| ms-sql-ntlm-info:   
|   10.10.11.51:1433:   
|     Target_Name: SEQUEL  
|     NetBIOS_Domain_Name: SEQUEL  
|     NetBIOS_Computer_Name: DC01  
|     DNS_Domain_Name: sequel.htb  
|     DNS_Computer_Name: DC01.sequel.htb  
|     DNS_Tree_Name: sequel.htb  
|_    Product_Version: 10.0.17763  
|_ssl-date: 2025-03-24T12:28:59+00:00; 0s from scanner time.  
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
|_ssl-date: 2025-03-24T12:28:58+00:00; 0s from scanner time.  
| ssl-cert: Subject: commonName=DC01.sequel.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb  
| Not valid before: 2024-06-08T17:35:00  
|_Not valid after:  2025-06-08T17:35:00  
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
|_ssl-date: 2025-03-24T12:28:58+00:00; 0s from scanner time.  
| ssl-cert: Subject: commonName=DC01.sequel.htb  
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb  
| Not valid before: 2024-06-08T17:35:00  
|_Not valid after:  2025-06-08T17:35:00  
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-title: Not Found  
|_http-server-header: Microsoft-HTTPAPI/2.0  
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port  
Device type: general purpose  
Running (JUST GUESSING): Microsoft Windows 2019 (90%)  
OS CPE: cpe:/o:microsoft:windows_server_2019  
Aggressive OS guesses: Windows Server 2019 (90%)  
No exact OS matches for host (test conditions non-ideal).  
Network Distance: 2 hops  
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
| smb2-time:   
|   date: 2025-03-24T12:28:22  
|_  start_date: N/A  
| smb2-security-mode:   
|   3:1:1:   
|_    Message signing enabled and required  
  
TRACEROUTE (using port 445/tcp)  
HOP RTT       ADDRESS  
1   328.51 ms 10.10.16.1  
2   534.46 ms 10.10.11.51  
  
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 135.55 seconds  



### Dati i tanti servizi, rifaccio una scan semplice con solamente i servizi e le versioni
  
Nmap scan report for 10.10.11.51  
Host is up (0.19s latency).  
Not shown: 987 filtered tcp ports (no-response)  
PORT     STATE SERVICE       VERSION  
53/tcp   open  domain        Simple DNS Plus  
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-24 12:30:21Z)  
135/tcp  open  msrpc         Microsoft Windows RPC  
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
445/tcp  open  microsoft-ds?  
464/tcp  open  kpasswd5?  
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000  
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)  
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows  

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 90.49 seconds  


## prova di uso delle credenziali date

 c'è un server smb, dopo la prima enumeration delle utenze senza password (senza successo)

 > smbclient -N -L

 crackmapexec smb 10.10.11.51 -u "rose" -p "KxEPkKe6R8su" --rid-brute | grep SidTypeUser

> SMB                      10.10.11.51     445    DC01             500: SEQUEL\Administrator (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             501: SEQUEL\Guest (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             502: SEQUEL\krbtgt (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             1000: SEQUEL\DC01$ (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             1103: SEQUEL\michael (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             1114: SEQUEL\ryan (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             1116: SEQUEL\oscar (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             1122: SEQUEL\sql_svc (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             1601: SEQUEL\rose (SidTypeUser)  
> SMB                      10.10.11.51     445    DC01             1607: SEQUEL\ca_svc (SidTypeUser)  

l'output completo senza grep sarebbe stato:

> SMB         10.10.11.51     445    DC01             498: SEQUEL\Enterprise Read-only Domain Controllers (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             500: SEQUEL\Administrator (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             501: SEQUEL\Guest (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             502: SEQUEL\krbtgt (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             512: SEQUEL\Domain Admins (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             513: SEQUEL\Domain Users (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             514: SEQUEL\Domain Guests (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             515: SEQUEL\Domain Computers (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             516: SEQUEL\Domain Controllers (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             517: SEQUEL\Cert Publishers (SidTypeAlias)  
> SMB         10.10.11.51     445    DC01             518: SEQUEL\Schema Admins (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             519: SEQUEL\Enterprise Admins (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             520: SEQUEL\Group Policy Creator Owners (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             521: SEQUEL\Read-only Domain Controllers (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             522: SEQUEL\Cloneable Domain Controllers (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             525: SEQUEL\Protected Users (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             526: SEQUEL\Key Admins (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             527: SEQUEL\Enterprise Key Admins (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             553: SEQUEL\RAS and IAS Servers (SidTypeAlias)  
> SMB         10.10.11.51     445    DC01             571: SEQUEL\Allowed RODC Password Replication Group (SidTypeAlias)  
> SMB         10.10.11.51     445    DC01             572: SEQUEL\Denied RODC Password Replication Group (SidTypeAlias)  
> SMB         10.10.11.51     445    DC01             1000: SEQUEL\DC01$ (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             1101: SEQUEL\DnsAdmins (SidTypeAlias)  
> SMB         10.10.11.51     445    DC01             1102: SEQUEL\DnsUpdateProxy (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             1103: SEQUEL\michael (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             1114: SEQUEL\ryan (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             1116: SEQUEL\oscar (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             1122: SEQUEL\sql_svc (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             1128: SEQUEL\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)  
> SMB         10.10.11.51     445    DC01             1129: SEQUEL\SQLRUserGroupSQLEXPRESS (SidTypeAlias)  
> SMB         10.10.11.51     445    DC01             1601: SEQUEL\rose (SidTypeUser)  
> SMB         10.10.11.51     445    DC01             1602: SEQUEL\Management Department (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             1603: SEQUEL\Sales Department (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             1604: SEQUEL\Accounting Department (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             1605: SEQUEL\Reception Department (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             1606: SEQUEL\Human Resources Department (SidTypeGroup)  
> SMB         10.10.11.51     445    DC01             1607: SEQUEL\ca_svc (SidTypeUser)  


accedo con l'utente dato a inizio macchina e vedo a quali share posso accedere

> smbclient -L //10.10.11.51 -U rose

inserisco la pass e ottengo:

>	Sharename       Type      Comment  
>	---------       ----      -------  
>	Accounting Department Disk        
>	ADMIN$          Disk      Remote Admin  
>	C$              Disk      Default share  
>	IPC$            IPC       Remote IPC  
>	NETLOGON        Disk      Logon server share   
>	SYSVOL          Disk      Logon server share   
>	Users           Disk        

Dalle tabelle enumerate prima



COPIANDO IL FILE NON MI FUNZIONA. 

https://www.hyhforever.top/htb-escapetwo/