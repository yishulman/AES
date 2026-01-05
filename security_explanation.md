1. an AES key is something that is impossilbe for humans to remember, so we use a password that humans can remember.

2. a hash is something an hacker can crack very easily, he can brute force the hash and get the password easily. So what we do is we use pbkdf2_hmac its basicly uses salt and iterations to improve the hash.

Importance of Salting - it makes sure that even if two people have the same password their final hases will be diffrent.

Importance of Iterations - A function runs the hash algorithm (such as SHA-256) thousands or hundreds of thousands of times on the same password, so a brute force attack is useless.

3. 
Nonce (Number used Once) - A unique, random, or non-repeating value. we use it to ensure freshness. It prevents "Replay Attacks" where a hacker captures a valid message and sends it again to repeat an action (like a bank transfer).
But there is a catch, it must never be reused with the same secret key.

Tag (Authentication Tag) - a digital signature that is generated during encryption. we use it to ensure integrity and authenticity. It proves that the message has not been tampered with and that it truly came from the sender.
If even one bit of the message changes, the Tag will not match, and the message will be rejected.