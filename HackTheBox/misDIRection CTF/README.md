This CTF was so weird in the sense that there is so much to figure out, but welp, gotta persevere.

it starts off with unzipping the main file, use unzip instead of 7z or other alternatives because you will need the debug information.

You should get an output like this:
```
 extracting: .secret/S/1             
   creating: .secret/V/
 extracting: .secret/V/35            
   creating: .secret/F/
 extracting: .secret/F/2             
 extracting: .secret/F/19            
 extracting: .secret/F/27            
   creating: .secret/o/
   creating: .secret/H/
   creating: .secret/A/
   creating: .secret/f/
   creating: .secret/r/
   creating: .secret/m/
   creating: .secret/B/
 extracting: .secret/B/23            
   creating: .secret/a/
   creating: .secret/O/
   creating: .secret/h/
   creating: .secret/t/
   creating: .secret/2/
 extracting: .secret/2/34            
   creating: .secret/7/
   creating: .secret/R/
 extracting: .secret/R/7             
 extracting: .secret/R/3             
   creating: .secret/b/
   creating: .secret/z/
 extracting: .secret/z/18            
   creating: .secret/j/
 extracting: .secret/j/10            
 extracting: .secret/j/12            
   creating: .secret/P/
   creating: .secret/y/
   creating: .secret/d/
 extracting: .secret/d/13            
   creating: .secret/Y/
   creating: .secret/q/
   creating: .secret/c/
   creating: .secret/6/
   creating: .secret/8/
   creating: .secret/U/
 extracting: .secret/U/9             
   creating: .secret/p/
 extracting: .secret/p/32            
   creating: .secret/W/
   creating: .secret/N/
 extracting: .secret/N/25            
 extracting: .secret/N/11            
 extracting: .secret/N/31            
 extracting: .secret/N/33            
   creating: .secret/g/
   creating: .secret/n/
   creating: .secret/e/
 extracting: .secret/e/5             
   creating: .secret/1/
 extracting: .secret/1/30            
 extracting: .secret/1/22            
   creating: .secret/s/
 extracting: .secret/s/24            
   creating: .secret/i/
   creating: .secret/3/
   creating: .secret/I/
   creating: .secret/D/
 extracting: .secret/D/26            
   creating: .secret/X/
 extracting: .secret/X/29            
 extracting: .secret/X/21            
 extracting: .secret/X/17            
   creating: .secret/Z/
   creating: .secret/4/
   creating: .secret/k/
   creating: .secret/9/
 extracting: .secret/9/36            
   creating: .secret/J/
 extracting: .secret/J/8             
   creating: .secret/C/
 extracting: .secret/C/4             
   creating: .secret/v/
   creating: .secret/M/
   creating: .secret/0/
 extracting: .secret/0/6             
   creating: .secret/G/
   creating: .secret/E/
 extracting: .secret/E/14            
   creating: .secret/Q/
   creating: .secret/K/
   creating: .secret/5/
 extracting: .secret/5/16            
   creating: .secret/x/
 extracting: .secret/x/15            
   creating: .secret/l/
   creating: .secret/u/
 extracting: .secret/u/20            
 extracting: .secret/u/28            
   creating: .secret/L/
   creating: .secret/T/
   creating: .secret/w/
```

Best of luck from here, because you will need to spend a lot of time removing and sorting things.
Firstly, you need every directory that has a number associated with it, like this one `.secret/u/20`, the numbers should range from 1-36, you can discard the rest.

Sort the numbers in ascending order from 1-36, and then filter out the letters associated with them, it should look like this `SFRCe0RJUjNjdEx5XzFuX1BsNDFuX1NpN2V9`

base64 decode it and you get the flag.
