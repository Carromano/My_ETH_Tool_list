# Easy Machine's solutions

## Code - LINUX

- python flask exploit per le credenziali
- hashcat per crackare l'hash MD5
- accesso in ssh -> file .sh con SUID

## dog - LINUX

- .git esposto
- admin panel con remote file inclusion
- **WEB SHELL** per trovare users
- ssh per user flag
- sudo -l -> programma con SUID impostato

## Escape Two - LINUX

- smbclient enumeration and exploitation
- MSSQL exploitation (stored procedures)
- Active directory and certificate exploitation (PRIVESC)
- NTHASH and KERBEROS TICKET CRACKING (easy lvl)

## Planning
- Sito online con un template/framework vulnerabile
- online fuzzing con ffuf
- CVE exploit
- Reverse shell 
- container exploitation
- crontab per fare privesc


## Titanic
- LFI
- Password Cracking
- Fuzzing and Searching in Remote PC
- Vulnerable Software exploitation -> magick


## Fluffy



# Medium Machine's solutions

## Cypher
- exploit di una vulnerabilità nota (Cypher Injection) per ottenere una reverse shell
- Eseguibile con SUID attivo
- Leak di file inseriti come parametri all'eseguibile con SUID (flag di root)

## Environment
- Laravel Environment Bypass vulnerability
- WebShell PHP tramite caricamento immagini
- crack delle chiavi GPG (procedura online) per ottenere password
- exploit di ENV_KEEP: `env_keep+="ENV BASH_ENV"` per fare privesc