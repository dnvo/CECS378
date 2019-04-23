import os
import json
from MyencryptMAC import MyencryptMAC, MydecryptMAC
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

# Encrypting to a file path 
def MyFileEncryptMAC(filepath):
    encKey = os.urandom(keysize)    # generate a random key for enc and mac 
    macKey = os.urandom(keysize)
    
    plainTextFile = open(filepath, 'rb');   # Reading file in and encrypt it
    message = plainTextFile.read()
    (cipherText, iv,tag) = MyencryptMAC(message,encKey, macKey)

    # write back to an encrypted file
    extension = Path(filepath).suffix # grabs extension of file
    out_file = open(filepath , "wb") #make a new file to write in binary
    out_file.write(cipherText) #write to the new file
    out_file.close() #close the file
    return cipherText, iv, encKey,tag,macKey, extension

# Inverse of encrypting to file, this method lets us decrypt the cipher text from the encrypted file
def MyFileDecryptMAC(filepath,encKey, iv,tag, macKey):
    file = open(filepath,"rb")      #open a file to decrypt
    
    content=file.read()     #read the file
    
    m=MydecryptMAC(content, key,iv, tag, HMACKey)   # Decrypt the contents using MAC Decrypt
    
    # Write the content back to the filepath 
    out_file1 = open(filepath, "wb") #make a new file
    out_file1.write(m) #write a new file
    out_file1.close() #close that file
    return m
