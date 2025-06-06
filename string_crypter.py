import base64
import os

class StringCrypter:
    def __init__(self, key):
        if not key:
            raise ValueError("Error: Key cannot be empty.")
        # Store key as bytes for consistent XOR operation
        self.key = key.encode('utf-8')

    def encrypt(self, plaintext):
        try:
            plain_bytes = plaintext.encode('utf-8')
            key_bytes = self.key
            key_length = len(key_bytes)
            # Use bytearray for mutable sequence of bytes
            cipher_bytes = bytearray(len(plain_bytes))

            for i in range(len(plain_bytes)):
                cipher_bytes[i] = plain_bytes[i] ^ key_bytes[i % key_length]
            
            # Encode result to Base64 and then decode to utf-8 string
            return base64.b64encode(cipher_bytes).decode('utf-8')
        except Exception as e:
            # Wrap original exception for better debugging
            raise RuntimeError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_data):
        try:
            # Ensure encrypted_data is bytes for b64decode
            cipher_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            key_bytes = self.key
            key_length = len(key_bytes)
            plain_bytes = bytearray(len(cipher_bytes))

            for i in range(len(cipher_bytes)):
                plain_bytes[i] = cipher_bytes[i] ^ key_bytes[i % key_length]
            
            return plain_bytes.decode('utf-8')
        except base64.binascii.Error as e: # Specific error for bad base64
            raise RuntimeError(f"Error: Decryption failed. Invalid Base64 data.") from e
        except Exception as e:
            raise RuntimeError(f"Error: Decryption failed: {e}") from e

def generate_salt(length_in_bytes=16):
    """Generates a cryptographically secure random salt and returns its hex representation."""
    salt_bytes = os.urandom(length_in_bytes)
    return salt_bytes.hex() # Converts bytes to a hex string

def process_string(operation_type, data):
    static_key = "test_key" 
    user_ip = "" # Kept for consistency with PHP/Java versions
    dynamic_key = user_ip + static_key

    crypter = StringCrypter(dynamic_key)

    try:
        if operation_type == 'e':
            salt = generate_salt(16) # 16 bytes of salt -> 32 hex characters
            data_with_salt = salt + data
            return crypter.encrypt(data_with_salt)
        elif operation_type == 'd':
            decrypted_data = crypter.decrypt(data)
            # Salt is 32 characters (16 bytes hex encoded)
            if len(decrypted_data) < 32: 
                 raise RuntimeError("Error: Decrypted data too short to contain salt.")
            # original_salt = decrypted_data[:32] # Salt is not used after extraction
            return decrypted_data[32:]
        else:
            return "Error: Invalid operation type"
    except Exception as e:
        # Return error message, similar to PHP/Java
        return f"Error: {str(e)}"

if __name__ == "__main__":
    data_to_encrypt = "This is a secret message."
    print(f"Original Data: {data_to_encrypt}")

    # Encrypt using Python
    encrypted_string_py = process_string('e', data_to_encrypt)
    print(f"Encrypted (Python): {encrypted_string_py}")

    # Decrypt using Python
    decrypted_string_py = process_string('d', encrypted_string_py)
    print(f"Decrypted (Python): {decrypted_string_py}")

    # Verify Python internal encryption/decryption
    if data_to_encrypt == decrypted_string_py:
        print("Python Encryption and Decryption successful!")
    else:
        print("Python Encryption and Decryption FAILED.")
        print(f"Expected: {data_to_encrypt}")
        print(f"Got: {decrypted_string_py}")

    print("\n--- Interoperability Test ---")
    
    # Test Python decrypting data encrypted by PHP/Java
    # Example from Java output: "Hello from Java for PHP!" encrypted
    # QFRAFW9SAEsWUBdFZl1RTxJVS0U+ClccRQAQQm5eABg8AB8YMEsDCxsIUz4+HQRZEgoBVA8jNVg=
    php_java_encrypted = "QFRAFW9SAEsWUBdFZl1RTxJVS0U+ClccRQAQQm5eABg8AB8YMEsDCxsIUz4+HQRZEgoBVA8jNVg="
    expected_decryption = "Hello from Java for PHP!"
    print(f"\nAttempting to decrypt (in Python) a string encrypted by PHP/Java:")
    print(f"Encrypted string: {php_java_encrypted}")
    decrypted_in_python = process_string('d', php_java_encrypted)
    print(f"Decrypted in Python: {decrypted_in_python}")
    if decrypted_in_python == expected_decryption:
        print(f"Python decryption of PHP/Java string successful!")
    else:
        print(f"Python decryption of PHP/Java string FAILED.")
        print(f"Expected: {expected_decryption}")
        print(f"Got: {decrypted_in_python}")

    # Test Python encrypting data for PHP/Java to decrypt
    data_for_php_java = "Hello from Python for PHP/Java!"
    print(f"\nAttempting to encrypt (in Python) a string for PHP/Java to decrypt:")
    print(f"Original string: {data_for_php_java}")
    python_encrypted_for_others = process_string('e', data_for_php_java)
    print(f"Encrypted by Python: {python_encrypted_for_others}")
    print(f"Take this string and try to decrypt it using processString('d', ...) in PHP or Java.")
