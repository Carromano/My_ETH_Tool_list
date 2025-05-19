# Cypher

IP: 10.10.11.57

<!-- https://www.hyhforever.top/htb-cypher/ -->

# NMAP

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-19 20:43 CEST
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 20:44 (0:00:06 remaining)
Stats: 0:00:53 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.30% done; ETC: 20:44 (0:00:00 remaining)
Nmap scan report for 10.10.11.57
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
**22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)**
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
**80/tcp open  http    nginx 1.24.0 (Ubuntu)**
|_http-title: Did not follow redirect to http://cypher.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=5/19%OT=22%CT=1%CU=40423%PV=Y%DS=2%DC=I%G=Y%TM=682B
OS:7C1E%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A)SEQ(S
OS:P=106%GCD=1%ISR=10A%TI=Z%CI=Z%TS=C)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II
OS:=I)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=7)OPS(O1=M542ST11NW7%O2=M5
OS:42ST11NW7%O3=M542NNT11NW7%O4=M542ST11NW7%O5=M542ST11NW7%O6=M542ST11)WIN(
OS:W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0
OS:%O=M542NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=O%F=AS%RD=0%Q=)T1(R=Y%DF=Y%
OS:T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T
OS:=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(
OS:R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.08 seconds

# Fuzzing

> ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt  -H "Host: FUZZ.cypher.thm" -u http://10.10.11.57

Ci avrebbe messo ore:

> dirsearch -u cypher.htb -t 50 -x 404

output:
```
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/carromano/My_ETH_Tool_list/HTB/VPN's Configurations/reports/_cypher.htb/_25-05-19_20-53-53.txt

Target: http://cypher.htb/

[20:53:54] Starting: 
[20:54:18] 200 -    5KB - /about
[20:54:18] 200 -    5KB - /about.html
[20:54:44] 307 -    0B  - /api  ->  /api/docs
[20:54:44] 307 -    0B  - /api/  ->  http://cypher.htb/api/api
[20:55:05] 307 -    0B  - /demo  ->  /login
[20:55:06] 307 -    0B  - /demo/  ->  http://cypher.htb/api/demo
[20:55:32] 200 -    4KB - /login.html
[20:55:32] 200 -    4KB - /login
[20:56:26] 301 -  178B  - /testing  ->  http://cypher.htb/testing/

Task Completed

```

# Exploit

