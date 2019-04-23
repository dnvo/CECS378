# file encryption algorithm
def MyfileEncrypt(filepath):
    key = os.urandom(32)
    
    # Read the entire file as a single byte string
    with open(filepath, 'rb') as f:
        data = f.read()

    result = Myencrypt(data, key)
    ext = os.path.splitext(file_path)[1]
    result += (key, ext)
    
    input_enc_filepath = input("Enter a file path for encrypted file output such as \"encrypted_image\": ")
    
    image_result = open(input_enc_filepath + ext, 'wb') # create a writable image and write the decoding result
    image_result.write(result[0])
    
    return result

# file dencryption algorithm
def MyfileDecrypt(enc_filepath, iv, key, ext):
    
    with open(enc_filepath, 'rb') as f:
        data = f.read()
    
    input_dec_filepath = input("Enter a file path for decrypted file output such as \"decrypted_image\": ")

    file_name = input_dec_filepath + ext
    plaintext = Mydecrypt(data, iv, key)
    image_result = open(file_name, 'wb') # create a writable image and write the decoding result
    image_result.write(plaintext)


# ----------------------
#Execution code
file_path = os.path.abspath("image.png")
ct, iv, key, ext = MyfileEncrypt(file_path)
input_enc_filepath = input("Enter a file path for previously encrypted file: ")
MyfileDecrypt(input_enc_filepath+ext, iv, key, ext)
