# CSCI373 HW1 Task 1: input and store username/password pair in 'password.txt' with encrypted password
import getpass
import os
import hashlib
import math

def encryptPass(plaintext, salt):
    key = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, 100000)
    return key.hex()

def getEntropy(input):
    hasUppercase = any(char.isupper() for char in input)
    hasLowercase = any(char.islower() for char in input)
    hasNumbers = any(char.isdigit() for char in input)
    hasSymbols = False
    if not (input.isalnum()):
        hasSymbols = True
    b = len(input)
    a=0;
    if(hasSymbols):
        #The presence of symbols means I assume all ascii chars are possibilities
        a=95
    #all cases below, we know hasSymbols is False
    elif(hasLowercase and not hasUppercase and not hasNumbers) or (hasUppercase and not hasLowercase and not hasNumbers):
        #one case, no symbols, no numbers
        a=26
    elif hasUppercase and hasLowercase and not hasNumbers:
        #both cases, no numbers, no symbols
        a=52
    elif (hasUppercase and not hasLowercase and hasNumbers) or (hasLowercase and not hasUppercase and hasNumbers):
        #one case plus numbers, no symbols
        a=36
    elif(hasUppercase and hasLowercase and hasNumbers and not hasSymbols):
        #both cases and numbers, no symbols
        a=62
    print(f"Possible Characters: {a}")
    print(f"Length: {b}")
    entropy = math.log2(a**b)
    print(f"Bits of entropy {entropy}")

def makeUser():
    username = input("Enter a Username: ")
    plaintext=getpass.getpass(prompt='Enter a password')
    salt = os.urandom(32)
    keyHash=encryptPass(plaintext, salt)
    passwordtxt = open('password.txt', "a")
    passwordtxt.write(username+":")
    #print(f"SALT {salt}")
    #print(f"SALTHEX: {salt.hex()}")
    #print(f"KEYHASH: {keyHash}")
    passwordtxt.write(salt.hex())
    passwordtxt.write(keyHash+"\n")
    getEntropy(plaintext)

makeUser()