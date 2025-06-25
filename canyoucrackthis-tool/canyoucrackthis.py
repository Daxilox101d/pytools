import hashlib

print(
    """
 ██████  █████  ███    ██     ██    ██  ██████  ██    ██      ██████ ██████   █████   ██████ ██   ██     ████████ ██   ██ ██ ███████ 
██      ██   ██ ████   ██      ██  ██  ██    ██ ██    ██     ██      ██   ██ ██   ██ ██      ██  ██         ██    ██   ██ ██ ██      
██      ███████ ██ ██  ██       ████   ██    ██ ██    ██     ██      ██████  ███████ ██      █████          ██    ███████ ██ ███████ 
██      ██   ██ ██  ██ ██        ██    ██    ██ ██    ██     ██      ██   ██ ██   ██ ██      ██  ██         ██    ██   ██ ██      ██ 
 ██████ ██   ██ ██   ████        ██     ██████   ██████       ██████ ██   ██ ██   ██  ██████ ██   ██        ██    ██   ██ ██ ███████ 
                                                                                                                                     
                                                                                                                                                                                                                                                                                                                                                                    
    
    Made By : @jester
    Python 3.13.0
    """
)

# ================== Hash Functions =========================
class HashAlgo:
    def sha256(self, clairtext):
        hash = hashlib.sha256(clairtext.encode())
        return hash.hexdigest()

    def sha1(self, clairtext):
        hash = hashlib.sha1(clairtext.encode())
        return hash.hexdigest()


    def sha512(self, clairtext):
        hash = hashlib.sha512(clairtext.encode())
        return hash.hexdigest()


    def md5(self, clairtext):
        hash = hashlib.md5(clairtext.encode())
        return hash.hexdigest()
#================================================================
#=========================== To get the hash type ================================
def hashtype(hash):
    number_of_charachters = 0
    for i in hash:
        number_of_charachters += 1
    if number_of_charachters == 64:
        return "sha-256"
        
    elif number_of_charachters == 128:
        return "sha-512"
        
    elif number_of_charachters == 40:
        return "sha-1"

    elif number_of_charachters == 32:
       return "md5"
    else:
        return
    
#======================================================================================
Hasher = HashAlgo()

user_hash = input("What is the hash that you want to crack: ").strip()


array_to_check = []

htype = hashtype(user_hash)
if htype == "sha-256":
    print(f"Probably The hash algo is: {htype}")
    wordlist = input("Enter the word list path that you want to use to crack the hash: ")
    try:
        with open(wordlist, "r", encoding="utf-8", errors='replace') as plain:
            for line in plain:
                password_to_test = line.strip()
                                        
                plain_to_hash = Hasher.sha256(password_to_test)

                if plain_to_hash == user_hash:
                    print(f"""
                        ========================================
                        The Password was cracked successfully!!
                        ========================================
                        The Password is: {password_to_test}
                        ========================================
                        """)
                    array_to_check.append(password_to_test)
                    break
            if not array_to_check:
                print("This list does not contain a valid password. Please try a different list.")        
    except FileNotFoundError:
        print(f"The file '{wordlist}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
            

elif htype == "sha-1":
    print(f"Probably The hash algo is: {htype}")
    wordlist = input("Enter the word list path that you want to use to crack the hash: ")
    try:
        with open(wordlist, "r", encoding="utf-8", errors='replace') as plain:
            for line in plain:
                password_to_test = line.strip()
                    
                plain_to_hash = Hasher.sha1(password_to_test)
                    
                if plain_to_hash == user_hash:
                    print(f"""
                        ========================================
                        The Password was cracked successfully!!
                        ========================================
                        The Password is: {password_to_test}
                        ========================================
                        """)
                    array_to_check.append(password_to_test)
                    break
            if not array_to_check:
                print("This list does not contain a valid password. Please try a different list.")    
    except FileNotFoundError:
        print(f"The file at '{wordlist}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


elif htype == "sha-512":
    print(f"Probably The hash algo is: {htype}")
    wordlist = input("Enter the word list path that you want to use to crack the hash: ")
    try:
        with open(wordlist, "r", encoding="utf-8", errors='replace') as plain:
            for line in plain:
                password_to_test = line.strip()
                        
                plain_to_hash = Hasher.sha512(password_to_test)
                        
                if plain_to_hash == user_hash:
                    print(f"""
                        ========================================
                        The Password was cracked successfully!!
                        ========================================
                        The Password is: {password_to_test}
                        ========================================
                        """)
                    array_to_check.append(password_to_test)
                    break
            if not array_to_check:
                print("This list does not contain a valid password. Please try a different list.")        
    except FileNotFoundError:
        print(f"The file at '{wordlist}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

elif htype == "md5":
    print(f"Probably The hash algo is: {htype}")
    wordlist = input("Enter the word list path that you want to use to crack the hash: ")
    try:
        with open(wordlist, "r", encoding="utf-8", errors='replace') as plain:
            for line in plain:
                password_to_test = line.strip()
                        
                plain_to_hash = Hasher.md5(password_to_test)
                                        
                if plain_to_hash == user_hash:
                    print(f"""
                        ========================================
                        The Password was cracked successfully!!
                        ========================================
                        The Password is: {password_to_test}
                        ========================================
                        """)
                    array_to_check.append(password_to_test)
                    break
            if not array_to_check:
                print("This list does not contain a valid password. Please try a different list.")        
    except FileNotFoundError:
        print(f"The file at '{wordlist}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
else:
    print("""
            ==========================================
            INVALID INPUT !
            ========================================
            Type of available hashes:
                        ==> sha-256
                        ==> sha-1
                        ==> sha-512
                        ==> md5
                """)
#==============================================================================
print("Thank you for using our tool! We hope you found it helpful and valuable.")
