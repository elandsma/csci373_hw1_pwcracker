import datetime
import itertools
import hashlib
import time
import math

def attemptCrack(salt, realHash):
    cracked = False
    characterList = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+={[}]\|<,>.?/:;\"'~`"
    while(not cracked):
        print("working...")
        dictionary = open("/usr/share/dict/words", "r")
        for word in dictionary:
            #remove trailing white space
            word = word.rstrip()
            key = hashlib.pbkdf2_hmac("sha256", word.encode(), salt, 100000)
            print(key)
            print(realHash)
            if (key == realHash):
                cracked = True
                return word
        print("Password not in dictionary.")
        return "still a mystery"
        break

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
    return math.log2(a**b)

passwordtxt = open('password.txt', 'r')
with open('password.txt', 'r') as passwordtxt:
        for line in passwordtxt:
            startTime = time.time()
            parsed=(line.split(':'))
            username=parsed[0]
            print(f"Cracking password for username: {username}")
            saltAndHash = parsed[1]
            salt = saltAndHash[:64]
            hash = saltAndHash[64:]
            salt = bytes.fromhex(salt)
            hash = bytes.fromhex(hash)
            cracked = attemptCrack(salt, hash)
            print(f"Password for {username} is {cracked}")
            print(f"{cracked} has {getEntropy(cracked)} bits of entropy")
            timetaken= (time.time() - startTime)
            print(f"Password  took {str(datetime.timedelta(seconds=timetaken))} hrs:min:sec to crack\n")
