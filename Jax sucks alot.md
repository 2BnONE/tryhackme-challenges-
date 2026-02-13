# Jax sucks alot - writeup 
**Difficulty:** Easy  

This challenge is very helpful for learning and practicing essential penetration testing skills, including: 
* Web Reconnaissance: Discovering hidden endpoints and understanding the application structure.
* Insecure Direct Object Reference (IDOR): Exploiting flawed access control to view unauthorized data.
* JSON Web Token (JWT) Manipulation: Understanding how to analyze and bypass authentication by tampering with tokens.
* Command Injection: Executing OS commands through vulnerable web inputs.
* Lateral Movement: Navigating through the system to gain access to different user accounts.

## 1. Ports Enumeration:  rustcan 
```bash
rustscan -a $ip
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------

Open 10.65.152.86:22
Open 10.65.152.86:80
```
after we know the open port now we will check the service and version by nmap 
## 2. Ports Enumeration: nmap 
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 af:e2:99:74:1e:38:79:6d:01:96:16:c3:cd:31:c8:bd (RSA)
|   256 bb:9d:8c:96:dc:0e:66:1c:05:aa:e8:23:f1:87:b5:a5 (ECDSA)
|_  256 94:5b:9c:fc:21:fd:f3:d0:59:42:c1:42:39:2a:c6:d2 (ED25519)
80/tcp open  http
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Fri, 13 Feb 2026 18:35:35 GMT
|     Connection: close
|     <html><head>
|     <title>Horror LLC</title>
|     <style>
|     body {
|     background: linear-gradient(253deg, #4a040d, #3b0b54, #3a343b);
|     background-size: 300% 300%;
|     -webkit-animation: Background 10s ease infinite;
|     -moz-animation: Background 10s ease infinite;
|     animation: Background 10s ease infinite;
|     @-webkit-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @-moz-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @keyframes Background {
|     background-position: 0% 50%
|     background-posi
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Fri, 13 Feb 2026 18:35:36 GMT
|     Connection: close
|     <html><head>
|     <title>Horror LLC</title>
|     <style>
|     body {
|     background: linear-gradient(253deg, #4a040d, #3b0b54, #3a343b);
|     background-size: 300% 300%;
|     -webkit-animation: Background 10s ease infinite;
|     -moz-animation: Background 10s ease infinite;
|     animation: Background 10s ease infinite;
|     @-webkit-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @-moz-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @keyframes Background {
|     background-position: 0% 50%
|_    background-posi
|_http-title: Horror LLC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.98%I=7%D=2/13%Time=698F6EF8%P=arm-apple-darwin24.4.0%r(G
SF:etRequest,E4B,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html\r\n
SF:Date:\x20Fri,\x2013\x20Feb\x202026\x2018:35:35\x20GMT\r\nConnection:\x2
SF:0close\r\n\r\n<html><head>\n<title>Horror\x20LLC</title>\n<style>\n\x20
SF:\x20body\x20{\n\x20\x20\x20\x20background:\x20linear-gradient\(253deg,\
SF:x20#4a040d,\x20#3b0b54,\x20#3a343b\);\n\x20\x20\x20\x20background-size:
SF:\x20300%\x20300%;\n\x20\x20\x20\x20-webkit-animation:\x20Background\x20
SF:10s\x20ease\x20infinite;\n\x20\x20\x20\x20-moz-animation:\x20Background
SF:\x2010s\x20ease\x20infinite;\n\x20\x20\x20\x20animation:\x20Background\
SF:x2010s\x20ease\x20infinite;\n\x20\x20}\n\x20\x20\n\x20\x20@-webkit-keyf
SF:rames\x20Background\x20{\n\x20\x20\x20\x200%\x20{\n\x20\x20\x20\x20\x20
SF:\x20background-position:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\
SF:x2050%\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x20100%\x2050
SF:%\n\x20\x20\x20\x20}\n\x20\x20\x20\x20100%\x20{\n\x20\x20\x20\x20\x20\x
SF:20background-position:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20}\n\x20
SF:\x20\n\x20\x20@-moz-keyframes\x20Background\x20{\n\x20\x20\x20\x200%\x2
SF:0{\n\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\x20\x20
SF:\x20\x20}\n\x20\x20\x20\x2050%\x20{\n\x20\x20\x20\x20\x20\x20background
SF:-position:\x20100%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x20100%\x20{
SF:\n\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\x20\x20\x
SF:20\x20}\n\x20\x20}\n\x20\x20\n\x20\x20@keyframes\x20Background\x20{\n\x
SF:20\x20\x20\x200%\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x20
SF:0%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x2050%\x20{\n\x20\x20\x20\x2
SF:0\x20\x20background-posi")%r(HTTPOptions,E4B,"HTTP/1\.1\x20200\x20OK\r\
SF:nContent-Type:\x20text/html\r\nDate:\x20Fri,\x2013\x20Feb\x202026\x2018
SF::35:36\x20GMT\r\nConnection:\x20close\r\n\r\n<html><head>\n<title>Horro
SF:r\x20LLC</title>\n<style>\n\x20\x20body\x20{\n\x20\x20\x20\x20backgroun
SF:d:\x20linear-gradient\(253deg,\x20#4a040d,\x20#3b0b54,\x20#3a343b\);\n\
SF:x20\x20\x20\x20background-size:\x20300%\x20300%;\n\x20\x20\x20\x20-webk
SF:it-animation:\x20Background\x2010s\x20ease\x20infinite;\n\x20\x20\x20\x
SF:20-moz-animation:\x20Background\x2010s\x20ease\x20infinite;\n\x20\x20\x
SF:20\x20animation:\x20Background\x2010s\x20ease\x20infinite;\n\x20\x20}\n
SF:\x20\x20\n\x20\x20@-webkit-keyframes\x20Background\x20{\n\x20\x20\x20\x
SF:200%\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\
SF:x20\x20\x20\x20}\n\x20\x20\x20\x2050%\x20{\n\x20\x20\x20\x20\x20\x20bac
SF:kground-position:\x20100%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x2010
SF:0%\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\x2
SF:0\x20\x20\x20}\n\x20\x20}\n\x20\x20\n\x20\x20@-moz-keyframes\x20Backgro
SF:und\x20{\n\x20\x20\x20\x200%\x20{\n\x20\x20\x20\x20\x20\x20background-p
SF:osition:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x2050%\x20{\n\x2
SF:0\x20\x20\x20\x20\x20background-position:\x20100%\x2050%\n\x20\x20\x20\
SF:x20}\n\x20\x20\x20\x20100%\x20{\n\x20\x20\x20\x20\x20\x20background-pos
SF:ition:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20}\n\x20\x20\n\x20\x20@k
SF:eyframes\x20Background\x20{\n\x20\x20\x20\x200%\x20{\n\x20\x20\x20\x20\
SF:x20\x20background-position:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x
SF:20\x2050%\x20{\n\x20\x20\x20\x20\x20\x20background-posi");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
No thing is imprtant for pot 80 it gust get the connect of the address we provide to, but we get intersteing inofrmations for port 22 the service and the OS   
## 3. Web Enumeraation: ffuf
```bash
└─$ gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u $IP -o gobuster.out 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.31.26
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/05 21:59:42 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/downloads            (Status: 301) [Size: 0] [--> downloads/]
/aboutus              (Status: 301) [Size: 0] [--> aboutus/]  
/admin                (Status: 301) [Size: 42] [--> /admin/]
...snip...
```


