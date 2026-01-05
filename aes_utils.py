import os
import hashlib
import string
from Crypto.Cipher import AES

def generate_aes_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Generates a 256-bit AES key from a password using PBKDF2.
    
    If salt is not provided, a new random salt is generated.
    
    Args:
        password (str): The input password.
        salt (bytes, optional): The salt to use. If None, a new salt is generated.
        
    Returns:
        tuple[bytes, bytes]: A tuple (key, salt) containing the 32-byte (256-bit) key and the generated salt.
                             You must store the salt to regenerate the same key later.
    """
    # TODO: Implement this function
    # 1. Validate password complexity (number, uppercase, special char) V
    # 2. Generate salt if not provided
    # 3. Use PBKDF2-HMAC-SHA256 with 600,000 iterations to derive the key

    if not any(char.isdigit() for char in password):
        raise ValueError("String must contain at least one number.")
        
    # 2. Check for at least one uppercase letter
    if not any(char.isupper() for char in password):
        raise ValueError("String must contain at least one uppercase letter.")
        
    if not any(char in string.punctuation for char in password):
        raise ValueError("String must contain at least one special character.")
    
    if salt is None:
        salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac('sha256', salt, 6000000, 32)

    key_salt_tuple = (key, salt)

    return key_salt_tuple

    


    #raise NotImplementedError("generate_aes_key not implemented")

def encrypt_file(file_path: str, password: str) -> str:
    """
    Encrypts a file using AES-256-GCM.
    
    The output file will have the same name with '.enc' appended.
    The file structure is: Salt (16 bytes) + Nonce (16 bytes) + Tag (16 bytes) + Ciphertext.
    
    Args:
        file_path (str): Path to the file to encrypt.
        password (str): Password to use for encryption.
        
    Returns:
        str: Path to the encrypted file.
    """
    # TODO: Implement this function
    # 1. Generate key and salt
    # 2. Create AES cipher in GCM mode
    # 3. Read file data
    # 4. Encrypt and digest
    # 5. Write Salt, Nonce, Tag, and Ciphertext to the output file
    raise NotImplementedError("encrypt_file not implemented")

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
