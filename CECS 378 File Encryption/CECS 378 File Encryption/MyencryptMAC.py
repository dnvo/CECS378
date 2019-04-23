import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from pathlib import Path #used to get file ext

#Global variables
encFileName = " "
decFileName = " "
filename =" "
keysize = 32

# Encryption Method using MAC
def MyencryptMAC(message,key, HMACKey):
    if(len(key) < 32): 
        raise ValueError("Invalid key, length must be 32 bytes (256bits)")
        return
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plainText = padder.update(message)
    padded_plainText += padder.finalize()
    
    blocksize = 16;
    iv = os.urandom(blocksize);
    
    cipherEncrypt = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    encryptor = cipherEncrypt.encryptor()
    
    cipherText = encryptor.update(padded_plainText) + encryptor.finalize()

    # Generate tag with HMAC
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
    h.update(cipherText) # gives the hmac the cipher text  
    tag = h.finalize() # Finalize the current context and return the message digest as bytes.
    return(cipherText, iv, tag)



# Decryption Method - Inverse of Encryption
def MydecryptMAC(cipherText, key,iv, tag, HMACKey):
    if(len(key) < 32): 
        raise ValueError("Invalid key, length must be 32 bytes (256bits)")
        return
     
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend()) # hashes algorithms
    h.update(cipherText) # hashes and authenticates bytes
    h.verify(tag) # compares bytes to current digest ( crytographic hash function containing a string of digits )
    # Finalize the current context and securely compare digest to signature

    cipherDecrypt = (Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())).decryptor()
    padded_plainText = cipherDecrypt.update(cipherText) + cipherDecrypt.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_plainText)
    message += unpadder.finalize()

    return message

## execution code    
#hmacKey = os.urandom(keysize)
#key = os.urandom(keysize)
#m = "test message cecs 378"
#result = MyencryptMAC(m, key, hmacKey)
#print("Encrypted Message:\n")
#print(result)
#print("\nDencrypted Message:")
#Mydecrypt(result[0], result[1], key).decode('utf8')
