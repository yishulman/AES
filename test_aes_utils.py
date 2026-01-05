import pytest
import os
from aes_utils import generate_aes_key, encrypt_file, decrypt_file

# --- generate_aes_key Tests ---

def test_generate_aes_key_valid():
    password = "Valid1Password!"
    key, salt = generate_aes_key(password)
    assert len(key) == 32  # 256 bits
    assert len(salt) == 16
    assert isinstance(key, bytes)
    assert isinstance(salt, bytes)

def test_generate_aes_key_consistency():
    password = "Valid1Password!"
    key1, salt1 = generate_aes_key(password)
    
    # Regenerate with same salt
    key2, salt2 = generate_aes_key(password, salt1)
    
    assert key1 == key2
    assert salt1 == salt2

def test_password_complexity_no_number():
    with pytest.raises(ValueError, match="Password must contain at least one number"):
        generate_aes_key("NoNumber!")

def test_password_complexity_no_uppercase():
    with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
        generate_aes_key("nouppercase1!")

def test_password_complexity_no_special():
    with pytest.raises(ValueError, match="Password must contain at least one special character"):
        generate_aes_key("NoSpecial1")

# --- Encryption/Decryption Tests ---

@pytest.fixture
def sample_file(tmp_path):
    d = tmp_path / "subdir"
    d.mkdir()
    p = d / "test_file.txt"
    content = b"This is some secret content for testing."
    p.write_bytes(content)
    return str(p), content

def test_encrypt_decrypt_cycle(sample_file):
    file_path, original_content = sample_file
    password = "TestPassword1!"
    
    # Encrypt
    encrypted_path = encrypt_file(file_path, password)
    assert os.path.exists(encrypted_path)
    assert encrypted_path.endswith(".enc")
    assert encrypted_path != file_path
    
    # Decrypt
    decrypted_path = decrypt_file(encrypted_path, password)
    assert os.path.exists(decrypted_path)
    
    # Verify content
    with open(decrypted_path, 'rb') as f:
        decrypted_content = f.read()
    
    assert decrypted_content == original_content

def test_decrypt_wrong_password(sample_file):
    file_path, _ = sample_file
    password = "TestPassword1!"
    wrong_password = "WrongPassword1!"
    
    encrypted_path = encrypt_file(file_path, password)
    
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_file(encrypted_path, wrong_password)

def test_decrypt_corrupted_file(sample_file):
    file_path, _ = sample_file
    password = "TestPassword1!"
    
    encrypted_path = encrypt_file(file_path, password)
    
    # Corrupt the file (change the last byte)
    with open(encrypted_path, 'rb+') as f:
        f.seek(-1, os.SEEK_END)
        f.write(b'\x00')
        
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt_file(encrypted_path, password)
