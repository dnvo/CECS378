from MyfileEncryptMAC import MyFileEncryptMAC, MyFileDecryptMAC
from MyencryptMAC import MyencryptMAC, MydecryptMAC
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.padding import MGF1 as uno
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from pathlib import Path #used to get file ext
#Global variables
encFileName = " "
decFileName = " "
filename =" "
keysize = 32

def generateKeyPair():  
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    publicKey = privateKey.public_key()   # generate public key
    return publicKey, privateKey
def keyValidation():
    if(os.path.exists('./378MyfileEncryptRSA/publicKey.pem') == False):
        publicKey, privateKey = generateKeyPair()

        privatePem = privateKey.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,
                                              encryption_algorithm=serialization.NoEncryption())

        publicPem = publicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        os.makedirs('./378MyfileEncryptRSA')
        privateFile = open ("378MyfileEncryptRSA/privateKey.pem", "wb") # Write private keys to file as binary 
        privateFile.write(privatePem)
        privateFile.close()
            
        publicFile = open ("378MyfileEncryptRSA/publicKey.pem", "wb") #Writes public keys to file as binary
        publicFile.write(publicPem)
        publicFile.close()
        print("Private Key & Public Key are created.")

def MyRSAencrypt(filepath, RSA_Publickey_filepath):
    backend=default_backend()

    C, IV, EncKey, tag, HMACKey, ext  = MyFileEncryptMAC(filepath)

    cdubd = os.getcwd()
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend = default_backend())

    RSACipher = public_key.encrypt(         
	EncKey+HMACKey, # concatenated 
	padding.OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return RSACipher, C, IV, ext, tag

def MyRSAdecrypt (filepath,RSACipher, C, IV, ext, RSA_Privatekey_filepath, tag):

    with open(RSA_Privatekey_filepath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password = None, backend = default_backend())

    key = private_key.decrypt(RSACipher, padding.OAEP(mgf= MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    EncKey=key[:32]
    HMACKey= key[-32:]

    m = MydecryptMAC(C, EncKey, IV, tag, HMACKey) #decrypt the message using decrypted key
    return m


keyValidation()
public_key = "../378MyfileEncryptRSA/publicKey.pem"
private_key = "../378MyfileEncryptRSA/privateKey.pem"
directory_path = "./EncryptMe"
os.chdir(directory_path)
cwd = os.getcwd()
print("Current directory:" + cwd)

javason = {} #create emtpy json (format for storing and transporting data)

for root, directory, files in os.walk(cwd):
    for filename in files:
        filename = os.path.join(root, filename)
        print("Encrypting " + filename + "...")
        RSACipher, C, IV, ext, tag = MyRSAencrypt(filename, public_key)

        name = os.path.splitext(str(filename))[0]
        jsn = {}
        jsn[name] = []
        jsn[name].append({
            "RSACipher": RSACipher.decode('latin-1'),
            "C": C.decode('latin-1'),
            "IV": IV.decode('latin-1'),
            "ext": ext,
            "tag": tag.decode('latin-1')})
        javason.update(jsn)

        with open(filename + '.json', 'w') as outfile:
            json.dump(javason, outfile, indent=4)
            outfile.close()