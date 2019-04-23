import os
import base64
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric
from cryptography.hazmat.primitives.asymmetric import rsa

# encryption method AES-CBC-256
def Myencrypt(message, key):
    
    #key length check
    if len(key)<32:
        return "Error: Key Length not long enough"
    
    try:
        message = message.encode()
    except:
        pass
    
    iv = os.urandom(16)   #generate an iv

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message)    #adds padding to get to next block size
    padded_data += padder.finalize()        #finalizes and returns remainder of data
    message = padded_data
        
    #calling the default AES CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    #creating an encryptor object
    encryptor = cipher.encryptor()
    
    #generating cipher text
    ct = encryptor.update(message) + encryptor.finalize()
    return(ct, iv) 


def Mydecrypt(ct, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    #creating a decryptor object
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(pt) # removes padding  
    pt += unpadder.finalize() #closes it
    



# execution code    
key = os.urandom(32)
m = "test message cecs 378"
result = Myencrypt(m, key)
print("Encrypted Message:\n")
print(result)
print("\nDencrypted Message:")
Mydecrypt(result[0], result[1], key).decode('utf8')
