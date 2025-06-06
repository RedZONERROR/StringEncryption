# string_crypter.rb
require 'securerandom'
require 'base64'

STATIC_KEY_RB = "test_key"
SALT_LENGTH_BYTES_RB = 16 # 16 bytes = 32 hex characters

def generate_salt_rb
  SecureRandom.hex(SALT_LENGTH_BYTES_RB)
end

def xor_strings_rb(s1_bytes, s2_bytes)
  return s1_bytes if s2_bytes.empty?
  s1_bytes.zip(s2_bytes.cycle).map { |b1, b2| b1 ^ b2 }
end

def encrypt_rb(plaintext, key_string)
  salt_hex = generate_salt_rb
  data_with_salt_string = salt_hex + plaintext

  data_with_salt_bytes = data_with_salt_string.bytes
  key_bytes = key_string.bytes

  xored_bytes_array = xor_strings_rb(data_with_salt_bytes, key_bytes)
  # Convert array of byte values back to a packed byte string
  xored_packed_bytes = xored_bytes_array.pack('C*')
  Base64.strict_encode64(xored_packed_bytes)
end

def decrypt_rb(encrypted_data, key_string)
  begin
    decoded_packed_bytes = Base64.strict_decode64(encrypted_data)
    decoded_bytes = decoded_packed_bytes.bytes # Get array of byte values
    key_bytes = key_string.bytes

    decrypted_with_salt_bytes_array = xor_strings_rb(decoded_bytes, key_bytes)
    # Convert array of byte values back to a packed byte string, then to UTF-8 string
    decrypted_with_salt_string = decrypted_with_salt_bytes_array.pack('C*').force_encoding('UTF-8')

    salt_hex_len = SALT_LENGTH_BYTES_RB * 2
    if decrypted_with_salt_string.bytesize < salt_hex_len
      puts "Decryption error: Decrypted data is too short to contain salt."
      return nil
    end
    # Substring based on character count, assuming salt is ASCII/UTF-8 compatible hex
    decrypted_with_salt_string[salt_hex_len..-1]
  rescue ArgumentError => e # Catches invalid base64 string
    puts "Decryption error: Invalid Base64 string. #{e.message}"
    nil
  rescue StandardError => e
    puts "Decryption error: #{e.message}"
    nil
  end
end

def process_string_rb(type, data)
  key = STATIC_KEY_RB
  case type
  when 'e'
    encrypt_rb(data, key)
  when 'd'
    decrypt_rb(data, key)
  else
    puts "Error: Invalid type specified. Use 'e' for encrypt or 'd' for decrypt."
    nil
  end
end

# Main test area
if __FILE__ == $0
  puts "--- Ruby String Encryption/Decryption Tests ---"

  original_text = "Hello from Ruby!"
  puts "Original Text: #{original_text}"

  encrypted_text = process_string_rb('e', original_text)
  if encrypted_text
    puts "Encrypted (Ruby): #{encrypted_text}"

    decrypted_text = process_string_rb('d', encrypted_text)
    if decrypted_text
      puts "Decrypted (Ruby): #{decrypted_text}"
      if decrypted_text == original_text
        puts "Ruby Encryption/Decryption Test: SUCCESSFUL"
      else
        puts "Ruby Encryption/Decryption Test: FAILED"
        puts "Expected: #{original_text}, Got: #{decrypted_text}"
      end
    else
      puts "Ruby Decryption FAILED (result was nil)."
    end
  else
    puts "Ruby Encryption FAILED (result was nil)."
  end

  puts "\n--- Interoperability Test (Ruby decrypts Python) ---"
  # Example: String "Hello from Python for Ruby!" encrypted by Python
  python_encrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=" # Placeholder
  expected_python_decryption = "Hello from Python for Ruby!" # Placeholder

  puts "Python Encrypted: #{python_encrypted}"
  decrypted_from_python = process_string_rb('d', python_encrypted)
  if decrypted_from_python
    puts "Decrypted by Ruby: #{decrypted_from_python}"
    if decrypted_from_python == expected_python_decryption
      puts "Ruby decryption of Python string: SUCCESSFUL (with correct Python output)"
    else
      puts "Ruby decryption of Python string: FAILED or placeholder data used."
      puts "Expected: #{expected_python_decryption}, Got: #{decrypted_from_python}"
    end
  else
    puts "Ruby decryption of Python string FAILED (result was nil)."
  end
  puts "Note: For the Python interop test to be meaningful, replace 'python_encrypted' with actual output from your Python script for the string '#{expected_python_decryption}'."


  puts "\n--- Interoperability Test (Ruby encrypts for others) ---"
  ruby_msg_for_others = "Hello from Ruby for other languages!"
  ruby_encrypted_for_others = process_string_rb('e', ruby_msg_for_others)
  if ruby_encrypted_for_others
    puts "Ruby Encrypted for others (Original: '#{ruby_msg_for_others}'): #{ruby_encrypted_for_others}"
    puts "Take this string and try to decrypt it using process_string('d', ...) in other languages."
  else
    puts "Ruby encryption for others FAILED (result was nil)."
  end
end
