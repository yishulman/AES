import os
import hashlib
import string
from Crypto.Cipher import AES

def generate_aes_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    if not any(char.isdigit() for char in password):
        raise ValueError("String must contain at least one number.")
        
    if not any(char.isupper() for char in password):
        raise ValueError("String must contain at least one uppercase letter.")
        
    if not any(char in string.punctuation for char in password):
        raise ValueError("String must contain at least one special character.")
    
    if salt is None:
        salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac('sha256', salt, 6000000, 32)

    key_salt_tuple = (key, salt)

    return key_salt_tuple

def encrypt_file(file_path: str, password: str) -> str:
    
    key, salt = generate_aes_key(password, salt=None)

    cipher = AES.new(key, AES.MODE_GCM)

    with open (file_path, "r") as fileToEnc:
        text = fileToEnc.read()

    ciphertext, tag = cipher.encrypt_and_digest(text)


    enc_file_path = file_path + ".enc"

    with open(enc_file_path, "wb") as writeFileToEnc:
        writeFileToEnc.write(salt)      
        writeFileToEnc.write(cipher.nonce) 
        writeFileToEnc.write(tag)    
        writeFileToEnc.write(ciphertext) 

    return enc_file_path



def decrypt_file(file_path: str, password: str) -> str:
    """
    Decrypts a file encrypted with encrypt_file.
    
    Args:
        file_path (str): Path to the encrypted file.
        password (str): Password to use for decryption.
        
    Returns:
        str: Path to the decrypted file.
    """
    # TODO: Implement this function
    # 1. Read Salt, Nonce, Tag, and Ciphertext from the file
    # 2. Regenerate key using the extracted salt
    # 3. Create AES cipher in GCM mode with the nonce
    # 4. Decrypt and verify
    # 5. Write decrypted data to output file (remove .enc or add .dec)
    raise NotImplementedError("decrypt_file not implemented")

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
