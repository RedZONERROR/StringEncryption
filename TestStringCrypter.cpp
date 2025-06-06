#include "StringCrypter.h" // Our header-only library
#include <iostream>

int main() {
    std::string data_to_encrypt = "This is a secret message.";
    std::cout << "Original Data: " << data_to_encrypt << std::endl;

    // Encrypt using C++ (from header-only library)
    std::string encrypted_string = process_string_cpp('e', data_to_encrypt);
    std::cout << "Encrypted (C++): " << encrypted_string << std::endl;

    // Decrypt using C++
    std::string decrypted_string = process_string_cpp('d', encrypted_string);
    std::cout << "Decrypted (C++): " << decrypted_string << std::endl;

    if (data_to_encrypt == decrypted_string) {
        std::cout << "C++ Encryption and Decryption successful!" << std::endl;
    } else {
        std::cout << "C++ Encryption and Decryption FAILED." << std::endl;
        std::cout << "Expected: " << data_to_encrypt << std::endl;
        std::cout << "Got: " << decrypted_string << std::endl;
    }

    std::cout << "\n--- Interoperability Test (C++ decrypts Python) ---" << std::endl;
    // String "Hello from Python for PHP/Java!" encrypted by Python:
    // W1dAFGgJAUwVUEtBZ1pQHUNcFhI8XAEYQARCRWlaXU0gDRoHfwIWWRVFABE8GQANVAgWBywKAhxaWGkUVGy1LNTEkSjkVKQpE
    std::string python_encrypted = "W1dAFGgJAUwVUEtBZ1pQHUNcFhI8XAEYQARCRWlaXU0gDRoHfwIWWRVFABE8GQANVAgWBywKAhxaWGkUVGy1LNTEkSjkVKQpE";
    std::string expected_python_decryption = "Hello from Python for PHP/Java!";
    std::cout << "Python Encrypted: " << python_encrypted << std::endl;
    std::string decrypted_from_python = process_string_cpp('d', python_encrypted);
    std::cout << "Decrypted by C++: " << decrypted_from_python << std::endl;
    if (expected_python_decryption == decrypted_from_python) {
        std::cout << "C++ decryption of Python string successful!" << std::endl;
    } else {
        std::cout << "C++ decryption of Python string FAILED." << std::endl;
        std::cout << "Expected: " << expected_python_decryption << std::endl;
        std::cout << "Got: " << decrypted_from_python << std::endl;
    }

    std::cout << "\n--- Interoperability Test (C++ encrypts for others) ---" << std::endl;
    std::string cpp_encrypted_for_others = process_string_cpp('e', "Hello from C++ for other languages!");
    std::cout << "C++ Encrypted for others: " << cpp_encrypted_for_others << std::endl;
    std::cout << "Take this string and try to decrypt it using process_string('d', ...) in other languages." << std::endl;

    return 0;
}
