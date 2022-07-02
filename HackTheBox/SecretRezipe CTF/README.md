# SecretRezipe

SecretRezipe has 2 solutions, One uses the concept of a BREACH attack (Which I'm frankly not the best at) while the other is a tool to crack the zip encryption.

We start by going to the IP address provided to us, which should look like this:

![Image](images/1.png)

At the end of the website, you are given an option to append your own ingredients and have a zip file which is password protected. Since the website doesn't really have any user-input to take advantage of, I concluded that the "secret ingredient" that they were talking about would be the flag.

We are also given files which tell us the structure of the website, along with how the encryption works and where the flag is located in the webserver. Fortunate for us, in `misc_secret_rezipe/src/src/config/config.js` and `misc_secret_rezipe/src/src/route.js`, my above hypothesis is confirmed by this line of text:

### config.js:
```
try {
     var FLAG = fs.readFileSync("/flag.txt")
} catch (e) {
    var FLAG = "HTB{fake_flag_for_testing}"
}
module.exports = {
  FLAG: FLAG,
  PASSWORD: crypto.randomUUID()
}
```

### route.js:
```
...

router.post('/ingredients', (req, res) => {
  let data = `Secret: ${FLAG}`
  
...

const tempPath = os.tmpdir() + '/' + crypto.randomBytes(16).toString('hex')
  fs.mkdirSync(tempPath);
  fs.writeFileSync(tempPath + '/ingredients.txt', data)
  child_process.execSync(`zip -P ${PASSWORD} ${tempPath}/ingredients.zip ${tempPath}/ingredients.txt`)
```

This just means that the flag is included in the zip file that is created on the webpage. It also tells us that the password is made by a function called `crypto.randomUUID()` which makes a 36 bit random value (I read a bit about how its crackable, but to do that you'll need a lot of processing power and would be very difficult if not impossible to do). We also see that it uses the zip function, which by default uses the legacy zip encryption (also known as ZipCrypto or Zip 2.0). Compared to a 36 bit random value, cracking ZipCrypto is very easy. Lastly, we get an idea of how the flag is written: `Secret: HTB{ value }`

## Exploit:

We will use tools like bkcrack (or pkcrack, they're the same thing) which can be found here: https://github.com/kimci86/bkcrack/releases/tag/v1.4.0 

To use this tool, we have to have some information on the parameters and how the attack works. bkcrack will need some plaintext information already present in the zip file and will need to know what the file path is. Using all the above, it will process a key which can be used to decipher the contents of the zip file. 

Start off with making a file called plain.txt which contains the following `Secret:HTB{` (Pro-Tip: use xxd or hexeditor to make sure that the plain.txt file has the exact text, sometimes a `.` is appended and that will make the entire cracking process useless). Secondly, download an empty file from the website (What I mean is that don't add any information and just click `Write and Zip`). Lastly, use a command like this :

```
bkcrack -L ingredients.zip
```

This will give us the filepath of the zip, which should look something like this: `tmp/df3f9de90f827a264844c0e00cd22294/ingredients.txt`. With this, the following command can be used:

```
./bkcrack -c tmp/df3f9de90f827a264844c0e00cd22294/ingredients.txt -C ingredients.zip -p plain.txt
```

You will get an output that looks like this `c68e3710 c49cbb37 f828cfae`. This is the keys that will be used to decipher ingredients.txt in ingredients.zip. To get the flag, type the following command:

```
./bkcrack -c tmp/df3f9de90f827a264844c0e00cd22294/ingredients.txt -C /ingredients.zip -k c68e3710 c49cbb37 f828cfae -d OUTPUT_FILE
```

type something like a.txt as your OUTPUT_FILE and then do `cat a.txt` to get the flag.
