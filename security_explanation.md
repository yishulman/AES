Why use a password instead of an AES key directly?
AES isnt good for humans. And Passwords are easy to rember but are easy to guess. A Key Derivation Function (KDF) is the best of both worlds :).

PBKDF2 Benefits
Why PBKDF2 instead of a simple hash?
A simple hash is extremely fast and vulnerable to brute-force and rainbow-table attacks. PBKDF2 helps stop it by: Applying many iterations to slow down guessing which makes each password guess expemsive, dramatically reducing attack feasibility.


Importance of Salting
A salt is a random value added to a password before the key. It ensures:
Identical passwords produce diferent keys
Rainbow tables are useless
Attacks must be done per user/file
Salts are not secret and are stored alongside the encrypted data.

Importance of Iterations
Iterations determine how many times the hash function runs during key derivation. More iterations:
Slightly slow down legitimate users
Massively slow down attaclers
This makes large-scale brute-force attacks impractical.


Nonce (Number Used Once)
A unique value for each encryption
Not secret
Must never be reused with the same key
Ensures encryption uniqueness and prevents catastrophic attacks

Authentication Tag
A cryptographic integrity check generated during encryption
Verified during decryption
Detects tampering, corruption, or wrong passwords
If tag verification fails, decryption must fail.