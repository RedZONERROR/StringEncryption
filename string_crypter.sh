#!/bin/bash

# string_crypter.sh

STATIC_KEY="test_key"
SALT_HEX_LEN=32 # 16 bytes * 2 hex chars

# Function to generate 16 random bytes as a 32-character hex string
generate_salt_sh() {
    openssl rand -hex 16
}

# Function to XOR data with a key using Perl
# $1: data string (salt_hex + plaintext)
# $2: key string
xor_string_sh() {
    local data_to_xor="$1"
    local key="$2"
    # Ensure perl handles UTF-8 correctly for input data and key
    # The data_to_xor is already salt_hex + plaintext, so it's a string.
    # Perl will operate on its byte representation.
    echo -n "$data_to_xor" | perl -CSDA -pe '
        BEGIN{
            # Get key from environment or argument; here, passed as arg to perl script
            $k = shift @ARGV;
            binmode(STDIN, ":bytes"); # Treat STDIN as raw bytes
            binmode(STDOUT, ":bytes"); # Treat STDOUT as raw bytes
            @key_bytes = unpack("C*", $k);
            $key_len = scalar @key_bytes;
            $idx = 0;
            $/ = \1; # Read one byte at a time
        }
        $_ = chr(ord($_) ^ $key_bytes[$idx++ % $key_len]);
    ' "$key"
}

encrypt_sh() {
    local plaintext="$1"
    local key="$STATIC_KEY"

    local salt_hex
    salt_hex=$(generate_salt_sh)
    if [[ -z "$salt_hex" ]]; then
        echo "Error: Failed to generate salt." >&2
        return 1
    fi

    local data_with_salt_string="${salt_hex}${plaintext}"

    # XOR and then Base64 encode
    # The output of xor_string_sh is raw (potentially binary) bytes
    xor_string_sh "$data_with_salt_string" "$key" | base64 -w 0 # -w 0 for no line wraps
}

decrypt_sh() {
    local encrypted_data="$1"
    local key="$STATIC_KEY"

    # Base64 decode, then XOR
    local decrypted_with_salt_bytes
    decrypted_with_salt_bytes=$(echo -n "$encrypted_data" | base64 -d -w 0 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        echo "Error: Invalid Base64 string." >&2
        return 1
    fi
    
    # The output of xor_string_sh is the string (salt_hex + plaintext)
    local decrypted_with_salt_string
    decrypted_with_salt_string=$(xor_string_sh "$decrypted_with_salt_bytes" "$key")
    if [[ $? -ne 0 ]]; then
        echo "Error: XOR decryption failed." >&2
        return 1
    fi

    if [[ ${#decrypted_with_salt_string} -lt $SALT_HEX_LEN ]]; then
        echo "Error: Decrypted data too short to contain salt." >&2
        return 1
    fi

    # Extract plaintext
    echo -n "${decrypted_with_salt_string:$SALT_HEX_LEN}"
}

process_string_sh() {
    local operation_type="$1"
    local data="$2"

    if [[ "$operation_type" == "e" ]]; then
        encrypt_sh "$data"
    elif [[ "$operation_type" == "d" ]]; then
        decrypt_sh "$data"
    else
        echo "Error: Invalid type. Use 'e' for encrypt or 'd' for decrypt." >&2
        return 1
    fi
}

# --- Test Section ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then # Check if script is executed directly
    echo "--- Bash String Encryption/Decryption Tests ---"

    original_text="Hello from Bash! With Ümlauts and €uro signs."
    echo "Original Text: $original_text"

    encrypted=$(process_string_sh "e" "$original_text")
    if [[ $? -eq 0 && -n "$encrypted" ]]; then
        echo "Encrypted (Bash): $encrypted"
        decrypted=$(process_string_sh "d" "$encrypted")
        if [[ $? -eq 0 ]]; then # Decrypt might return empty string on success if original was empty
            echo "Decrypted (Bash): $decrypted"
            if [[ "$decrypted" == "$original_text" ]]; then
                echo "Bash Encryption/Decryption Test: SUCCESSFUL"
            else
                echo "Bash Encryption/Decryption Test: FAILED"
                echo "Expected: $original_text"
                echo "Got:      $decrypted"
            fi
        else
            echo "Bash Decryption FAILED."
        fi
    else
        echo "Bash Encryption FAILED."
    fi

    echo ""
    echo "--- Interoperability Test (Bash decrypts Python example) ---"
    # Placeholder - replace with actual encrypted string from Python for "Hello from Python for Bash!"
    python_encrypted="NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q="
    expected_python_decryption="Hello from Python for Bash!"

    echo "Python Encrypted (Placeholder): $python_encrypted"
    decrypted_from_python=$(process_string_sh "d" "$python_encrypted")
    if [[ $? -eq 0 ]]; then
        echo "Decrypted by Bash: $decrypted_from_python"
        if [[ "$decrypted_from_python" == "$expected_python_decryption" ]]; then
            echo "Bash decryption of Python string: SUCCESSFUL (if placeholder matches actual)"
        else
            echo "Bash decryption of Python string: FAILED or placeholder data used."
            echo "Expected: $expected_python_decryption"
            echo "Got:      $decrypted_from_python"
        fi
    else
         echo "Bash decryption of Python string FAILED."
    fi
    echo "Note: For the interop test to be meaningful, replace 'python_encrypted' with actual output."

    echo ""
    echo "--- Interoperability Test (Bash encrypts for others) ---"
    bash_msg_for_others="Hello from Bash for other languages!"
    bash_encrypted_for_others=$(process_string_sh "e" "$bash_msg_for_others")
    if [[ $? -eq 0 && -n "$bash_encrypted_for_others" ]]; then
        echo "Bash Encrypted for others (Original: '$bash_msg_for_others'): $bash_encrypted_for_others"
        echo "Take this string and try to decrypt it using other language scripts."
    else
        echo "Bash encryption for others FAILED."
    fi
fi
