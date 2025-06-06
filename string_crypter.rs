// string_crypter.rs

use base64::{encode as base64_encode_rust, decode as base64_decode_rust};
use rand::RngCore;
use hex; // For hex encoding the salt

const STATIC_KEY_RUST: &str = "test_key";
const SALT_LENGTH_BYTES_RUST: usize = 16; // 16 bytes = 32 hex characters

// Generates a random salt of SALT_LENGTH_BYTES_RUST and returns it as a hex-encoded string.
fn generate_salt_rust() -> Result<String, String> {
    let mut salt_bytes = [0u8; SALT_LENGTH_BYTES_RUST];
    if let Err(e) = rand::thread_rng().try_fill_bytes(&mut salt_bytes) {
        return Err(format!("Failed to generate salt bytes: {}", e));
    }
    Ok(hex::encode(salt_bytes))
}

// Performs XOR operation between input bytes and key bytes.
fn xor_bytes_rust(input: &[u8], key: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    if key_len == 0 { // Avoid division by zero if key is empty
        return input.to_vec();
    }
    input.iter().enumerate().map(|(i, &byte)| byte ^ key[i % key_len]).collect()
}

// Encrypts plaintext: prepends salt, XORs with key, then Base64 encodes.
fn encrypt_rust(plaintext: &str, key: &str) -> Result<String, String> {
    let salt = generate_salt_rust()?;
    let mut data_with_salt: Vec<u8> = Vec::new();
    data_with_salt.extend_from_slice(salt.as_bytes()); // Salt is hex-encoded string
    data_with_salt.extend_from_slice(plaintext.as_bytes());

    let xored_data = xor_bytes_rust(&data_with_salt, key.as_bytes());
    Ok(base64_encode_rust(&xored_data))
}

// Decrypts Base64 encoded data: decodes, XORs with key, then removes salt.
fn decrypt_rust(encrypted_data: &str, key: &str) -> Result<String, String> {
    let decoded_data = base64_decode_rust(encrypted_data)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    
    let decrypted_with_salt_bytes = xor_bytes_rust(&decoded_data, key.as_bytes());

    // Salt is a hex string of length SALT_LENGTH_BYTES_RUST * 2
    let salt_hex_len = SALT_LENGTH_BYTES_RUST * 2;
    if decrypted_with_salt_bytes.len() < salt_hex_len {
        return Err("Decrypted data too short to contain salt".to_string());
    }

    let original_plaintext_bytes = &decrypted_with_salt_bytes[salt_hex_len..];
    String::from_utf8(original_plaintext_bytes.to_vec())
        .map_err(|e| format!("UTF-8 conversion failed: {}", e))
}

// Main processing function.
pub fn process_string_rust(op_type: char, data: &str) -> Result<String, String> {
    let key = STATIC_KEY_RUST;
    match op_type {
        'e' => encrypt_rust(data, key),
        'd' => decrypt_rust(data, key),
        _ => Err(format!("Invalid operation type: {}. Use 'e' or 'd'", op_type)),
    }
}

fn main() {
    println!("--- Rust String Encryption/Decryption Tests ---");

    let original_text = "Hello from Rust!";
    println!("Original Text: {}", original_text);

    match process_string_rust('e', original_text) {
        Ok(encrypted_text) => {
            println!("Encrypted (Rust): {}", encrypted_text);
            match process_string_rust('d', &encrypted_text) {
                Ok(decrypted_text) => {
                    println!("Decrypted (Rust): {}", decrypted_text);
                    if decrypted_text == original_text {
                        println!("Rust Encryption/Decryption Test: SUCCESSFUL");
                    } else {
                        println!("Rust Encryption/Decryption Test: FAILED");
                        println!("Expected: {}, Got: {}", original_text, decrypted_text);
                    }
                }
                Err(e) => eprintln!("Rust Decryption FAILED: {}", e),
            }
        }
        Err(e) => eprintln!("Rust Encryption FAILED: {}", e),
    }

    println!("\n--- Interoperability Test (Rust decrypts Python) ---");
    // Example: String "Hello from Python for Rust!" encrypted by Python
    // Python: StringCrypter().process_string('e', "Hello from Python for Rust!")
    // Replace with actual Python output
    let python_encrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q="; // Placeholder
    let expected_python_decryption = "Hello from Python for Rust!"; // Placeholder

    println!("Python Encrypted: {}", python_encrypted);
    match process_string_rust('d', python_encrypted) {
        Ok(decrypted_from_python) => {
            println!("Decrypted by Rust: {}", decrypted_from_python);
            if decrypted_from_python == expected_python_decryption {
                println!("Rust decryption of Python string: SUCCESSFUL (with correct Python output)");
            } else {
                println!("Rust decryption of Python string: FAILED or placeholder data used.");
                println!("Expected: {}, Got: {}", expected_python_decryption, decrypted_from_python);
            }
        }
        Err(e) => eprintln!("Rust decryption of Python string FAILED: {}", e),
    }
    println!("Note: For the Python interop test to be meaningful, replace 'python_encrypted' with actual output from your Python script for the string '{}'.", expected_python_decryption);


    println!("\n--- Interoperability Test (Rust encrypts for others) ---");
    let rust_message_for_others = "Hello from Rust for other languages!";
    match process_string_rust('e', rust_message_for_others) {
        Ok(rust_encrypted_for_others) => {
            println!("Rust Encrypted for others (Original: '{}'): {}", rust_message_for_others, rust_encrypted_for_others);
            println!("Take this string and try to decrypt it using process_string('d', ...) in other languages.");
        }
        Err(e) => eprintln!("Rust encryption for others FAILED: {}", e),
    }
}


//#[dependencies]
//Cargo.toml
//base64 = "0.21" # Or the latest compatible version
//rand = "0.8"    # Or the latest compatible version
//hex = "0.4"     # Or the latest compatible version