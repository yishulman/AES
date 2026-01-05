from aes_utils import decrypt_file

file_to_decrypt = "my_secret.txt.enc"
password = "My_Secure_Password1!"

filePath = decrypt_file(file_to_decrypt, password)

