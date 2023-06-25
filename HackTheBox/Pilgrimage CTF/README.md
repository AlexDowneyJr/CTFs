# Pilgrimage

## Enumeration:

Start off with an nmap scan:
```vim
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.19s latency).
Not shown: 65451 closed tcp ports (conn-refused), 82 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This leaks the `.git` repository, with this we can run something like `git-dumper` to extract everything.
I tried to look into the commits and branches but there was nothing of value there so I decided to look into the files extracted instead.

```vim
total 26976
drwxr-xr-x 6 kali kali     4096 Jun 25 17:15 .
drwxr-xr-x 3 kali kali     4096 Jun 25 16:38 ..
drwxr-xr-x 6 kali kali     4096 Jun 25 14:00 assets
-rwxr-xr-x 1 kali kali     5538 Jun 25 14:00 dashboard.php
drwxr-xr-x 7 kali kali     4096 Jun 25 14:00 .git
-rwxr-xr-x 1 kali kali     9250 Jun 25 14:00 index.php
-rwxr-xr-x 1 kali kali     6822 Jun 25 14:00 login.php
-rwxr-xr-x 1 kali kali       98 Jun 25 14:00 logout.php
-rwxr-xr-x 1 kali kali 27555008 Jun 25 14:00 magick
-rwxr-xr-x 1 kali kali     6836 Jun 25 14:00 register.php
drwxr-xr-x 4 kali kali     4096 Jun 25 14:00 vendor
```

## Exploit:

Looking into the PHP files, you find out that the webapp is using BulletProof and ImageMagick (specifically 7.1.0). ImageMagick 7.1.0 is vulnerable to [CVE-2022-44268](https://github.com/voidz0r/CVE-2022-44268)

The Webapp is essentially taking the image, parsing it through ImageMagick and shrinking the image to a smaller size and then letting you download it. We have to exploit this by giving it a vulnerable PNG file to achieve LFI by writing file contents in hex to the output PNG. 

I try out with trying to do LFI for `/etc/passwd` and using `identify -v <RESULT_IMG>` on the image and you can get the hex output, convert it to text and see that you get the `/etc/passwd` contents. However from here I was having some trouble thinking where to get some valuable content from due to the lack of much config on this webapp. Looking into the PHP files again, we can see a `/var/db/pilgrimage` which is an SQLite File. I try to get that file using the exploit and then running it through [SQLite Online](https://sqliteonline.com/) where we can see a `users` table which has the following credentials: `emily:abigchonkyboi123`

We can SSH into the box with these credentials and get the User Flag in `/home/emily/user.txt`

## Privilege Escalation:

You can get the content for privilege escalation via 2 routes:
1. Linpeas will tell you that the `malwarescan.sh` executable is world readable and you can see the code from there
2. When you upload an image, you will see `pspy64` give this type of output:
```vim
2023/06/25 21:13:39 CMD: UID=0     PID=752    | /bin/bash /usr/sbin/malwarescan.sh 
2023/06/25 21:13:39 CMD: UID=0     PID=751    | /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/
```

Here are the contents for `malwarescan.sh`:
```
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

We can see `echo`, `sed`, `inotifywait`, `tail` and `binwalk` being executed on this script. This script essentially looks for any change in `/var/www/pilgrimage.htb/shrunk` and reads the contents of the file, It then tries to make a filename which is done by echo-ing the file contents, taking the last line and then using `sed` on it. The file is then run through `binwalk` which then looks through the blacklist to see if it has any of the blacklisted words. If it does then the file is removed, if it doesn't the file is extracted as normal.

Since `binwalk` is not a system command, I tried to look at the version and see if it has any vulnerabilities. The version on this machine is 2.3.2 which is vulnerable to RCE in [CVE-2022-4510](https://www.exploit-db.com/exploits/51249). 

You can simply generate an exploit PNG from the script above, open a netcat listener and then copy the exploit PNG to `/var/www/pilgrimage.htb/shrunk` and get the reverse shell. The reverse shell is a `sh` based one so you won't receive much output on your listener except one which says that connection was received but you can execute commands just fine.

Root flag will be in `/root/root.txt`
