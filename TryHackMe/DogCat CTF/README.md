# DogCat

This CTF is about exploiting a PHP application, LFI to RCE and breaking out of a docker container.

## Enumeration

Start off with an NMAP scan

```
nmap -sC -Pn -v -sV <IP_ADDR>
```

![Image](images/1.png)

This NMAP scan shows us that port 80 (Apache Webserver) and port 22 are running.

![Image](images/2.png)

Looking at the website, we see that there are 2 buttons. The Dog button will show us a picture of a dog, and the Cat button will show us a picture of a cat.

Looking at the URL, we see that there is a `?view=` parameter which changes to dog or cat when viewing either button. I happened to run `dogcat` as a parameter value and it gave me this error:

![Image](images/3.png)

This error message tells 2 things:
1. The parameter is looking for a filename (in this case, dog or cat) and automatically adds `.php` at the end of it.
2. If the parameter value doesn't have either `dog` or `cat` in the name, we don't get any errors but we can't view anything either. There is index.php being called, but the page source doesn't seem to have anything interesting.

This means, we have to try LFI and see if we can read the php files in this web application.

## Exploit

Here, we have to use PHP wrappers to read the PHP source code. More information here: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi--rfi-using-wrappers

I will be using this payload: `/?view=php://filter/convert.base64-encode/resource=<PHP_FILE>`

Running the above payload with dog as a value shows us this:

![Image](images/3.png)

Decoding the above base-64 string shows us that `dog.php` randomly picks between 1.jpg - 10.jpg. However, we want to go to step further and try to find out the code in index.php. For this, we will use this payload: `/?view=php://filter/convert.base64-encode/resource=dog/../index`

