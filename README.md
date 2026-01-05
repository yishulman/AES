# AES File Encryption/Decryption Assignment

This assignment involves implementing a secure file encryption and decryption tool using Python and the `pycryptodome` library. You will implement key derivation using PBKDF2 and authenticated encryption using AES-GCM.

## Prerequisites

1.  **Python 3.x** installed.
2.  Install required packages:
    ```bash
    pip install -r requirements.txt
    ```

## Files

*   `aes_utils.py`: The main script where you will implement the functionality.
*   `test_aes_utils.py`: Unit tests to verify your implementation.
*   `requirements.txt`: List of dependencies.

## Tasks

You need to implement three functions in `aes_utils.py`.

### 1. `generate_aes_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]`

This function derives a 256-bit AES key from a password.

**Requirements:**
*   **Password Complexity:** Validate that the password contains:
    *   At least one number.
    *   At least one uppercase letter.
    *   At least one special character (from `string.punctuation`).
    *   Raise a `ValueError` if any condition is not met.
*   **Salt:**
    *   If `salt` is `None`, generate a new random 16-byte salt using `os.urandom(16)`.
    *   If `salt` is provided, use it.
*   **Key Derivation:**
    *   Use `hashlib.pbkdf2_hmac`.
    *   Algorithm: `sha256`.
    *   Iterations: `600,000`.
    *   Key Length: `32` bytes (256 bits).
*   **Return:** A tuple `(key, salt)`.

### 2. `encrypt_file(file_path: str, password: str) -> str`

This function encrypts a file using AES-256-GCM.

**Requirements:**
1.  Generate a key and salt using `generate_aes_key(password)`.
2.  Create an AES cipher object in **GCM mode** (`AES.MODE_GCM`) using the generated key.
3.  Read the content of the file at `file_path`.
4.  Encrypt the data and generate an authentication tag using `cipher.encrypt_and_digest(data)`.
5.  Write the output to a new file named `<file_path>.enc`.
6.  **File Structure:** The output file must contain the following components in order:
    *   Salt (16 bytes)
    *   Nonce (16 bytes) - Available via `cipher.nonce`
    *   Tag (16 bytes)
    *   Ciphertext (variable length)
7.  Return the path to the encrypted file.

### 3. `decrypt_file(file_path: str, password: str) -> str`

This function decrypts a file created by `encrypt_file`.

**Requirements:**
1.  Read the encrypted file.
2.  Extract the components based on the file structure:
    *   First 16 bytes: Salt
    *   Next 16 bytes: Nonce
    *   Next 16 bytes: Tag
    *   Remaining bytes: Ciphertext
3.  Regenerate the key using `generate_aes_key(password, salt)`.
4.  Create an AES cipher object in **GCM mode** using the regenerated key and the extracted **nonce**.
5.  Decrypt and verify the data using `cipher.decrypt_and_verify(ciphertext, tag)`.
    *   If verification fails (e.g., wrong password or tampered file), `ValueError` will be raised by the library. Catch it and raise a new `ValueError` with a descriptive message.
6.  Write the decrypted data to a new file.
    *   If the input filename ends with `.enc`, remove it (e.g., `file.txt.enc` -> `file.txt`).
    *   Otherwise, append `.dec` (e.g., `file.txt` -> `file.txt.dec`).
7.  Return the path to the decrypted file.

### 4. Security Explanation

Create a new file named `security_explanation.md` and provide a detailed explanation for the following:

1.  **Password Usage:** Why do we need a password to generate the AES key why not use AES key directly?
2.  **PBKDF2 Benefits:** How does `pbkdf2_hmac` improve security compared to a simple hash?
    *   Discuss the importance of **Salting** 
    *   Discuss the importance of **Iterations** 
3. what is **Nonce** ans **Tag** ?

### 5. Decrypt my_secret.txt.enc

the password is "My_Secure_Password1!" the salt Nonce and Tag are in a file (fame format as you need to implement in encrypt_file)

## Testing

Run the provided unit tests to verify your implementation:

```bash
pytest test_aes_utils.py
```

You can also run the script directly to see the example usage output:

```bash
python aes_utils.py
```