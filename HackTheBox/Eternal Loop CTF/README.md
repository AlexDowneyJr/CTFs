Eternal Loop
============

Eternal Loop is a CTF that reminded me the terror of Bashic Calculator, but in a way eased me into being more accepting towads bash. Scripting is great, making small scripts to do tasks which will likely take hours is extremely satisfying and even if its not the best script, as long as it gets the job done it feels nice. Although I got a great insight into bash scripting, I do believe that I want to make a script that is more perfect and accomodating to where it doesn't look like a jumbled mess but more as a coheasive tool that gets the work done. Rant aside, lets start with the CTF:

We are given a .zip that is the Eternal\ Loop.zip and once we unzip that with the password provided to us, we are given 37366.zip, that we don't have a password to. Luckily, we have John the Ripper to help us out here. Use `zip2john 37366.zip > hash.txt` and follow that up with `john hash.txt` and we get the password which is 5900. Yay, lets unzip that and we get . . . another .zip. 

Yeah this CTF basically has you make a recursive unzipper which we have to use to bruteforce passwords (technically, the password is the .zip within the .zip when unzipping but I don't think a script can read output from an ongoing process, so let john do the work).

Disclaimer: My script isn't perfect, so to atone for my lack of expertise, I'll tell you everything you need to do from the script, to if the script fails, to getting the flag.

```
#!/bin/bash

oldfile=$1
hashfile=$2
outputfile=$3

while true ; do
    zip2john $oldfile > $hashfile #Make hash of .zip
    john $hashfile > $outputfile  #Crack the password of .zip and put the output in an output file
    
    pass=$(grep -o -E -m 1 "([0-9]{3,5})" $outputfile | head -1) # grep the password from the output file
    echo "$pass is password"  #This one was for my sanity because a lot of text goes by
    
    unzip -P $pass $oldfile   # Unzip the file with the password we acquired
    oldfile="$pass.zip"       # Set up the loop for the .zip inside the .zip
    echo "$oldfile is old file"  #Another one for my own sanity

done
```

In the above script, I made 3 files. I made a `aaa.sh`(The script file for the above code), `hash.txt` for storing the hash from john, `out.txt` for storing the output from hash and being able to grep it.

If you did the above unzipping exercise with me, don't forget to type this command `rm /home/lolboi/.john/john.pot`

Execute the script like this:
```
bash aaa.sh 37366.zip hash.txt out.txt
```
This bash script will execute perfectly while throwing a lot of output for a while, and then it will face a slight issue for which the `unzip --help` page will start showing up.

To fix this, run the following commands in order:
```
unzip -P 71 8778.zip 

bash aaa.sh 71.zip hash.txt out.txt
```

This error comes up because in my script, I only grep numbers of length 3 and above, doing less than that results in me taking random numbers in the john output which we don't need.

once the script starts running again, you will come across the script stopping or the script again throwing the `unzip --help` page. This means you have reached the end of the unzipping and need just one more unzip.

This will be the 6969.zip (nice) and you can use these commands to get the password for the last zip:
```
zip2john 6969.zip > hash.txt

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

unzip -P letmeinplease 6969.zip
```

The last zip gives us a file called `DoNotTouch` which is an SQLLite file. You can open the file by yourself or using an online viewer. I used this one: https://inloop.github.io/sqlite-viewer/

In the employees table, you will find the flag (Specifically the employee ID is 69, just make a query like this and you will see it : `SELECT Email FROM 'employees'` )
