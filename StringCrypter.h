#ifndef STRINGCRYPTER_H
#define STRINGCRYPTER_H

#include <string>
#include <vector>

// Base64 utility functions
std::string base64_encode(const std::string& in);
std::string base64_decode(const std::string& in);

class StringCrypter {
private:
    std::string key_bytes_; // Store key as string of bytes

public:
    StringCrypter(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& encrypted_data);

    static std::string generate_salt(int length_in_bytes = 16);
    static std::string process_string(char type, const std::string& data);
};

#endif // STRINGCRYPTER_H
