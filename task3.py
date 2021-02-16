# CSCI373 HW1 Task 2: dictionary attack 'password.txt' made in task1
import datetime
import hashlib
import time
import math

def attemptCrack(salt, realHash):
    """Dictionary attack: Goes through dictionary word by word. Sorts by word length. If no result, converts word to 1337speak. If no results, tries converting individual characters into 1337speak"""
    cracked = False
    while(not cracked):
        print("Checking all dictionary words, sorted by length...")
        for x in range(1,5):
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
        #run through the dictionary again the same way, but with swaps.
        print("\nDictionary words did not work. Trying character swaps...")
        for x in range(1,5):
            dictionary = open("/usr/share/dict/words", "r")
            print(f"checking words of length {x}......")
            print(f"checking with complete 1337sp34k...")
            for word in dictionary:
                if len(word) == x:
                    #remove trailing white space
                    word = word.rstrip()
                    #first let's try total 1337speak before doing individuals letters.
                    leetspeak = word
                    replacements = (    ('a', '4'), ('A', '4'),
                                        ('e', '3'), ('E', '3'),
                                        ('o', "0"), ('O', '0'),
                                        ('l', '1'), ('L', '1'),
                                        ('t', '+'), ('T', '+'),
                                        ('s', '5'), ('S', '5')
                                    )
                    for old, new in replacements:
                        leetspeak = leetspeak.replace(old, new)
                    key = hashlib.pbkdf2_hmac("sha256", leetspeak.encode(), salt, 100000)
                    if (key == realHash):
                        cracked = True
                        return leetspeak
            #total leetspeak didn't work. Let's try one letter at a time.
            dictionary = open("/usr/share/dict/words", "r")
            print(f"checking with individual letter swaps...")
            for word in dictionary:
                if len(word) == x:
                    #remove trailing white space
                    word = word.rstrip()
                    #saving copy of original word to reset character swaps
                    original = word
                    #change all 'e','E' to '3'
                    for letter in range(0, len(word)):
                        word = word.replace('e', '3')
                        word = word.replace('E', '3')
                    key = hashlib.pbkdf2_hmac("sha256", word.encode(), salt, 100000)
                    if (key == realHash):
                        cracked = True
                        return word
                    word = original
                    for letter in range(0, len(word)):
                        word = word.replace('a', '4')
                        word = word.replace('A', '4')
                    key = hashlib.pbkdf2_hmac("sha256", word.encode(), salt, 100000)
                    if (key == realHash):
                        cracked = True
                        return word
                    word = original
                    for letter in range(0, len(word)):
                        word = word.replace('o', '0')
                        word = word.replace('O', '0')
                    key = hashlib.pbkdf2_hmac("sha256", word.encode(), salt, 100000)
                    if (key == realHash):
                        cracked = True
                        return word
                    word = original
                    #change all 's','S' to '5'
                    for letter in range(0, len(word)):
                        word = word.replace('s', '5')
                        word = word.replace('S', '5')
                    key = hashlib.pbkdf2_hmac("sha256", word.encode(), salt, 100000)
                    if (key == realHash):
                        cracked = True
                        return word
                    word = original
        print("Password not in dictionary.")
        return "unknown"
        break

def getEntropy(input):
    """Calculates and returns the level of entropy for the input"""
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
    else:
        a=10
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
