import os
import hashlib
import string
from Crypto.Cipher import AES

def generate_aes_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    
    #Check for at least one number
    if not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one number.")

    # Check for at least one uppercase letter
    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")

    # Check for at least one special character
    if not any(char in string.punctuation for char in password):
        raise ValueError("Password must contain at least one special character.")
        
    if salt is None:
        salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000, 32)

    return (key, salt)

def encrypt_file(file_path: str, password: str) -> str:
    key, salt = generate_aes_key(password)
    AEScipher = AES.new(key, AES.MODE_GCM)

    with open (file_path, 'rb') as file:
        data = file.read()

    ciphertext, authTag = AEScipher.encrypt_and_digest(data)

    with open(file_path + ".enc", 'wb') as writeFile:
        writeFile.write(salt)      
        writeFile.write(AEScipher.nonce) 
        writeFile.write(authTag)    
        writeFile.write(ciphertext) 

    return file_path + ".enc"


def decrypt_file(file_path: str, password: str) -> str:
    with open(file_path, 'rb') as file:
        salt = file.read(16)  
        nonce = file.read(16) 
        authTag = file.read(16)  
        ciphertext = file.read() 

    key, salt = generate_aes_key(password, salt)

    AEScipher = AES.new(key, AES.MODE_GCM, nonce)

    try:
        data = AEScipher.decrypt_and_verify(ciphertext, authTag)
        
    except ValueError:
        raise ValueError("Decryption failed")

    if file_path.endswith(".enc"):
        file_path = file_path[:-4]
    else:
        file_path = file_path + ".dec"

    with open(file_path, "wb") as file:
        file.write(data)

    return file_path

if __name__ == "__main__":
    # Example usage
    try:
        pwd = "My_Secure_Password1!"
        
        # Test Key Generation
        print("Testing Key Generation...")
        try:
            key, salt = generate_aes_key(pwd)
            print(f"Generated Key (hex): {key.hex()}")
            print(f"Generated Salt (hex): {salt.hex()}")
        except NotImplementedError as e:
            print(e)
        
        # Test File Encryption
        test_file = "secret.txt"
        if not os.path.exists(test_file):
            with open(test_file, 'w') as f:
                f.write("This is a secret message.")

        if os.path.exists(test_file):
            print(f"\nTesting Encryption for {test_file}...")
            try:
                encrypted_file = encrypt_file(test_file, pwd)
                print(f"File '{test_file}' encrypted to '{encrypted_file}'")
                
                # Test File Decryption
                print(f"\nTesting Decryption for {encrypted_file}...")
                try:
                    decrypted_file = decrypt_file(encrypted_file, pwd)
                    print(f"File '{encrypted_file}' decrypted to '{decrypted_file}'")
                    
                    # Verify content
                    with open(decrypted_file, 'r') as f:
                        print("Decrypted content:")
                        print(f.read())
                except NotImplementedError as e:
                    print(e)
                except Exception as e:
                    print(f"Decryption failed: {e}")
            except NotImplementedError as e:
                print(e)
        else:
            print(f"Test file '{test_file}' not found.")
            
    except Exception as e:
        print(f"An error occurred: {e}")
