from aes_utils import decrypt_file

password = "My_Secure_Password1!"

file = "my_secret.txt.enc"

output_file_path = decrypt_file(file, password)

print(f"file is decrypted in {output_file_path}")