import datetime
import hashlib
import time
import math

def attemptCrack(salt, realHash):
    cracked = False
    while(not cracked):
        print("working...")
        for x in range(1,16):
            dictionary = open("/usr/share/dict/words", "r")
            print(f"checking words of length {x}...")
            for word in dictionary:
                # remove trailing white space
                word = word.rstrip()
                if len(word) == x:
                    key = hashlib.pbkdf2_hmac("sha256", word.encode(), salt, 100000)
                    if (key == realHash):
                        cracked = True
                        return word
        #dictionary didn't work, so now begin character substitutions

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
        a=95
    elif(hasLowercase and not hasUppercase and not hasNumbers) or (hasUppercase and not hasLowercase and not hasNumbers):
        a=26
    elif hasUppercase and hasLowercase and not hasNumbers:
        a=52
    elif (hasUppercase and not hasLowercase and hasNumbers) or (hasLowercase and not hasUppercase and hasNumbers):
        a=36
    elif(hasUppercase and hasLowercase and hasNumbers and not hasSymbols):
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
            print(f"Password took {str(datetime.timedelta(seconds=timetaken))} hrs:min:sec to crack\n")
