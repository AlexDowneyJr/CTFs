# Shoppy CTF

## Enumeration:

Start off with an NMAP scan

```vim
nmap -Pn -sV -sC -v 10.10.11.180

Nmap scan report for 10.10.11.180
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
|_  256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
80/tcp   open     http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://shoppy.htb
2968/tcp filtered enpp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Here we can see port 80 and port 22 open, and a redirection to `http://shoppy.htb`. We can add this to our `/etc/hosts` file and start directory fuzzing and possible subdomain enumeration.

Directory Fuzzing reveals the following endpoints:
1. `/admin`
2. `/login`

Subdomain Enumeration reveals the following subdomain:
1. `mattermost.shoppy.htb`

Looking at the directories first, `/login` is a login page which we can test to confirm if it is vulnerable to SQL injection. Entering `'` as username and password makes the webpage unresponsive which only further adds to my suspicion. SQLMap seemed to not work due to a possible WAF so I decided to try payloads manually.

## Exploit:

I tried the [Generic_Fuzz.txt](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Generic_Fuzz.txt) from PayloadsAllTheThings repo and the payload that seemed to work was this: `1'||'asd'||'`

With this, we can do authorization bypass and see the `/admin` page. On the top right, there is a page to search for users through their usernames. Since this also seems to connect to a database, I use the same payload `1'||'asd'||'` to see if it is vulnerable to SQL Injection and it worked. We see 2 users and their password hashes:
1. admin
2. josh

These were MD5 hashes, admin's hash did not get cracked but we were able to crack josh's hash: `6ebcea65320589ca4f2f1ce039975995:remembermethisway`

After this, we check out `mattermost.shoppy.htb` which also requires a login. We can use josh's credentials in order to log in and come across a chat service. Looking around we come across the following messages:

--- 
***Development Channel:***
  
josh:
>Hey @jaeger, when I was trying to install docker on the machine, I started learn C++ and I do a password manager. You can test it if you want, the program is on the deploy machine.


***Deploy Machine:***

jaeger:
>Hey @josh,
>For the deploy machine, you can create an account with these creds : username: jaeger password: Sh0ppyBest@pp! And deploy on it.

...

josh:
>Oh I forgot to tell you, that we're going to use docker for the deployment, so I will add it to the first deploy

---

These conversations give us 2 things:
1. Credentials for jaeger
2. Password manager on the target machine
3. Use of docker on the machine

Login to the machine with the credentials for jaeger. User flag will be found in `/home/jaeger/user.txt`

## Priv-Esc:

### jaeger to deploy:

In `/home/deploy` , we have a executable called password-manager (As mentioned above) which requires a password in order to give us credentials for deploy machine. There are 2 ways to get this password:
1. Reverse engineer the executable
2. Use `cat` or `xxd` 

Reading through it, you will come across `Sample` which is the password.

Running `sudo -l` will show us that we can run this executable as the deploy user via sudo.

```vim
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

We can run `su deploy` and enter its password shown above to login.

### deploy to root:

Running `id` on deploy will show you that it is part of the docker group. This had me looking through GTFObins wondering if there is any docker exploit and I ran across the following command:

```vim
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```

This command creates and runs an image of the machine in a docker container, effectively copying the entire machine into a docker container and letting us look at the machine via the container. This is still a container so I don't think we can add/change files and directories in the target machine but we can view the contents in `/root` for the flag.

Root flag can be found in `/root/root.txt`
