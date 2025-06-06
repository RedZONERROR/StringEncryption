# Cross-Language String Encryption Utility

This repository contains implementations of a simple string encryption and decryption utility across various programming languages. The goal is to provide interoperable encryption, allowing a string encrypted in one language to be decrypted in another, using a consistent scheme.

## Encryption Scheme

The encryption scheme employed is as follows:
1.  **Salt Generation**: A 16-byte random salt is generated.
2.  **Hex Encoding Salt**: The 16 random salt bytes are hex-encoded to produce a 32-character string (`salt_hex`).
3.  **Combine Salt and Plaintext**: The `salt_hex` string is prepended to the original plaintext string: `combined_string = salt_hex + original_plaintext`.
4.  **UTF-8 Encode**: The `combined_string` is converted to a byte array using UTF-8 encoding: `combined_bytes = combined_string.getBytes("UTF-8")`.
5.  **XOR Encryption**: The `combined_bytes` are XORed byte-by-byte with a static key: `"test_key"`. The key (also UTF-8 encoded) is repeated cyclically if shorter than the data.
6.  **Base64 Encoding**: The resulting XORed byte array is Base64 encoded to produce the final encrypted string.

Decryption reverses this process:
1.  Base64 Decode the encrypted string to get XORed bytes.
2.  XOR Decrypt these bytes with the static key (UTF-8 encoded) to get `decrypted_combined_bytes`.
3.  Convert `decrypted_combined_bytes` back to a string using UTF-8 encoding: `decrypted_combined_string`.
4.  Extract the first 32 characters from `decrypted_combined_string` as the `retrieved_salt_hex`.
5.  The remainder of `decrypted_combined_string` is the original plaintext.

## Implemented Languages

Below is a list of implemented languages, their respective files, and basic instructions for running them. All implementations aim to provide a `processString('e', "plaintext")` function for encryption and `processString('d', "encrypted_text")` for decryption, or an equivalent.

---

### 1. PHP
-   **File:** `StringEncryption.php`
-   **Usage:** Contains a `StringEncryption` class with a `processString($type, $data)` method.
-   **To Run:** Include the file and call the methods. Requires a PHP environment.
    ```php
    // <?php
    // require_once 'StringEncryption.php';
    // $crypter = new StringEncryption();
    // $encrypted = $crypter->processString('e', "Hello PHP");
    // echo "Encrypted: " . $encrypted . "\n";
    // $decrypted = $crypter->processString('d', $encrypted);
    // echo "Decrypted: " . $decrypted . "\n";
    // ?>
    ```

### 2. Java
-   **File:** `StringCrypter.java`
-   **Usage:** Contains a `StringCrypter` class with a static `processString(char type, String data)` method and a `main` method for tests.
-   **To Run:**
    ```bash
    javac StringCrypter.java
    java StringCrypter
    ```

### 3. Python
-   **File:** `string_crypter.py`
-   **Usage:** Contains a `StringCrypter` class and a `process_string(type_char, data_string)` function, with example usage in `if __name__ == "__main__":`.
-   **To Run:**
    ```bash
    python string_crypter.py
    ```

### 4. C# (.NET)
-   **File:** `StringCrypter.cs`
-   **Usage:** Contains a `StringCrypter` class with `ProcessString(char type, string data)` and a `Main` method for tests.
-   **To Run:** Requires .NET SDK.
    ```bash
    # Assuming StringCrypter.cs is in a project or compiled directly
    # dotnet run (if part of a project)
    # or
    csc StringCrypter.cs
    StringCrypter.exe
    ```
    *(Note: Compilation and execution were not fully tested due to potential environment constraints during development.)*

### 5. C++
-   **Files:**
    -   `StringCrypter.h` (Header-only library)
    -   `TestStringCrypter.cpp` (Example usage)
-   **Usage:** Include `StringCrypter.h` and use the `StringCrypter::processString(char type, const std::string& data)` function.
-   **To Compile & Run Example (e.g., with g++):**
    ```bash
    g++ TestStringCrypter.cpp -o test_cpp -std=c++11
    ./test_cpp
    ```

### 6. C
-   **Files:**
    -   `string_crypter.h` (Header file)
    -   `string_crypter.c` (Implementation)
    -   `test_string_crypter_c.c` (Example usage)
-   **Usage:** Link against `string_crypter.c` and use `process_string_c(char type, const char* data, char** result)`. Caller must `free(*result)`.
-   **To Compile & Run Example (e.g., with gcc):**
    ```bash
    gcc test_string_crypter_c.c string_crypter.c -o test_c
    ./test_c
    ```

### 7. JavaScript (Node.js & Browser)
-   **Files:**
    -   `stringCrypter.js` (Core logic, supports Node.js `require` and browser global)
    -   `testJs.html` (Browser test page)
-   **Usage:**
    -   **Node.js:** `const sc = require('./stringCrypter.js'); sc.processString('e', "data");`
    -   **Browser:** Include `stringCrypter.js` in a script tag. `processString` will be available globally.
-   **To Run (Node.js example):**
    ```bash
    node -e "const sc = require('./stringCrypter.js'); console.log(sc.processString('e', 'Hello JS'));"
    ```
    **To Run (Browser):** Open `testJs.html` in a web browser and check the console.

### 8. Go
-   **File:** `stringcrypter.go`
-   **Usage:** Contains `ProcessStringGo(operationType rune, data string)` and a `main` function for tests.
-   **To Run:**
    ```bash
    go run stringcrypter.go
    ```

### 9. Rust
-   **File:** `string_crypter.rs`
-   **Usage:** Contains `process_string_rust(operation_type: char, data: &str)` and a `main` function for tests.
-   **Dependencies (add to `Cargo.toml`):**
    ```toml
    [dependencies]
    base64 = "0.21" # Or latest compatible
    rand = "0.8"    # Or latest compatible
    hex = "0.4"     # Or latest compatible
    ```
-   **To Run (within a Cargo project):**
    ```bash
    # Example: cargo new rust_crypto_test && cd rust_crypto_test
    # Replace src/main.rs with string_crypter.rs content
    # Add dependencies to Cargo.toml
    cargo run
    ```

### 10. Lua
-   **File:** `string_crypter.lua`
-   **Usage:** Returns a module table. Use `M.process_string_lua(type, data)`. Contains test examples.
-   **Requirements:** Lua 5.3+ recommended for `bit32` library. For older versions, an external bitwise operations library might be needed.
-   **To Run:**
    ```bash
    lua string_crypter.lua
    ```

### 11. Kotlin
-   **File:** `StringCrypter.kt`
-   **Usage:** Contains `processStringKt(type: Char, data: String)` and a `main` function for tests.
-   **To Run:** Requires Kotlin compiler.
    ```bash
    kotlinc StringCrypter.kt -include-runtime -d StringCrypterKt.jar
    java -jar StringCrypterKt.jar
    ```

### 12. Dart (and Flutter)
-   **File:** `string_crypter.dart`
-   **Usage:** Contains `processStringDart(String type, String data)` and a `main` function for tests.
    -   **Dart CLI:** Run directly.
    -   **Flutter:** Copy `string_crypter.dart` into your Flutter project's `lib` directory and import it.
-   **To Run (Dart CLI):**
    ```bash
    dart string_crypter.dart
    ```

### 13. Swift
-   **File:** `StringCrypter.swift`
-   **Usage:** Contains `processStringSwift(type: Character, data: String)` and a `runSwiftTests()` function.
-   **To Run:** Requires Swift compiler.
    ```bash
    swift StringCrypter.swift
    ```
    (Or run in an Xcode Playground.)

### 14. Ruby
-   **File:** `string_crypter.rb`
-   **Usage:** Contains `process_string_rb(type, data)` and test code within `if __FILE__ == $0`.
-   **To Run:**
    ```bash
    ruby string_crypter.rb
    ```

### 15. Perl
-   **File:** `string_crypter.pl`
-   **Usage:** Contains `process_string_pl($type, $data)` and test code.
-   **Requirements:** `MIME::Base64` and `Encode` modules (Encode is usually core).
-   **To Run:**
    ```bash
    perl string_crypter.pl
    ```
    (Install modules if needed: `cpan MIME::Base64`)
-   **Interoperability Note:** The current Perl implementation (`string_crypter.pl`) has a deviation from the common scheme. It prepends the *raw 16 salt bytes* to the UTF-8 encoded plaintext before XORing. For full interoperability, the Perl script should be modified to prepend the *32-character hex string representation of the salt* to the plaintext string *before* the combined string is UTF-8 encoded (i.e., `encode_utf8(salt_hex_string . plaintext)` should be the data fed to XOR).

### 16. Scala
-   **File:** `StringCrypter.scala`
-   **Usage:** An object `StringCrypter` with `processStringScala(operationType: Char, data: String)` and a `main` method for tests.
-   **To Run:** Requires Scala compiler.
    ```bash
    scalac StringCrypter.scala
    scala StringCrypter
    ```

---

## Interoperability Testing

Each implementation includes placeholder tests for decrypting a string encrypted by another language (often Python as an example). To properly test interoperability:
1.  Encrypt a known string (e.g., "Hello from [SourceLanguage] for [TargetLanguage]!") using the source language script.
2.  Copy the resulting Base64 encoded string.
3.  Replace the placeholder `*_encrypted` variable in the target language's test section with this string.
4.  Run the target language's test script to verify successful decryption.

Similarly, each script generates an encrypted string that can be used to test decryption in other languages.

## Contributing

Feel free to add implementations in other languages or improve existing ones! Please ensure the core encryption logic remains consistent for interoperability. If you encounter issues or have suggestions, please open an issue or a pull request.
