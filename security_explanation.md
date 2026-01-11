1. AES key is not something that a normal person can remeber, so instead we use a normal password that everyone can remember, like '!MySecurePass123'.
2. A simple hash is to fast to crack by a hacker, the hacker can brute force the hash fast and get your password easily.
So instead we use pbkdf2_hmac.
What it does is using salt and iterations to improve on a regular hash.
- Salt is very important so two persons with the same password won't have the same key. Hackers use something called 'Rainbow Tables' that includes a database of premade hashes.
- Iterations is also very important, instead of running the hash once, PBKDF2 runs it a certin amount of times (in our case 600,000), so a brute force attack would become useless against it, and for us, as a user, the 1.5s wait is incomperable to the millions of seconds it will take for a hacker to go through every hash if there is 1.5s on top of every password.
3. Nonce and tag is something you get when you run AES in a GCM mode.
- Nonce (Number used Once).
it's a random number that is unique for every encryption with the same key.
So if you encrypt that same file twice with the same password, the result would be totally diffrent every time.
With that hackers can't identify patterns in the encrypted data.
- Tag (Authentication Tag).
It's a digital signature that gets created during the encryption procces.
It's job is to make sure that the file isn't being temperd.
During the Decryption the AES calculate the tag again and makes sure that it's the same as the one you saved, if even one bit doensn't match, it will raise an error.
