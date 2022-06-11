BabyEncryption CTF
==================

Growing up, I never have been great at math, this one really made me look deep and find out decryption works in tools.

We start off with a task file provided to us. It is a zip file containing a python file for encryption and an encoding file which is the message.

Since the file has been encrypted with modulus, you cannot reverse it unless you have the math and the brain behind that. I have neither so I will go the easy route, brute-forcing :D

here is the code for the buteforcing decryption:

```
msg = "6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921"

decrypt = ""

a = bytes.fromhex(msg) #individual bytes of hex characters

for aa in a: #brute-force process
    for decrypl in range(33,126):
        p = decrypl
        
        decrypl = ((123 * decrypl + 18) % 256)
        
        if decrypl == aa:
            decrypt += chr(p)
            break

print(decrypt) # this is the flag
```
