// test_string_crypter_c.c
#include "string_crypter.h"
#include <stdio.h>
#include <stdlib.h> // For free
#include <string.h> // For strcmp

int main() {
    printf("--- C String Encryption/Decryption Tests ---\n");

    const char *original_text = "Hello from C language!";
    char *encrypted_text_c = NULL;
    char *decrypted_text_c = NULL;
    int ret;

    printf("Original Text: %s\n", original_text);

    // Encrypt
    ret = process_string_c('e', original_text, &encrypted_text_c);
    if (ret == 0 && encrypted_text_c) {
        printf("Encrypted (C): %s\n", encrypted_text_c);
    } else {
        printf("C Encryption FAILED (ret code: %d)\n", ret);
        if(encrypted_text_c) free(encrypted_text_c);
        return 1;
    }

    // Decrypt
    ret = process_string_c('d', encrypted_text_c, &decrypted_text_c);
    if (ret == 0 && decrypted_text_c) {
        printf("Decrypted (C): %s\n", decrypted_text_c);
    } else {
        printf("C Decryption FAILED (ret code: %d)\n", ret);
        free(encrypted_text_c); // Clean up encrypted text
        if(decrypted_text_c) free(decrypted_text_c);
        return 1;
    }

    // Verify
    if (strcmp(original_text, decrypted_text_c) == 0) {
        printf("C Encryption/Decryption Test: SUCCESSFUL\n");
    } else {
        printf("C Encryption/Decryption Test: FAILED\n");
        printf("Expected: %s\n", original_text);
        printf("Got: %s\n", decrypted_text_c);
    }

    free(encrypted_text_c);
    free(decrypted_text_c);

    printf("\n--- Interoperability Test (C decrypts Python) ---\n");
    // This is an example string. Replace with actual output from Python:
    // Python: StringCrypter().process_string('e', "Hello from Python for C!")
    const char *python_encrypted_for_c = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q="; 
    const char *expected_python_decryption = "Hello from Python for C!"; 

    printf("Python Encrypted for C: %s\n", python_encrypted_for_c);
    char *decrypted_from_python = NULL;
    ret = process_string_c('d', python_encrypted_for_c, &decrypted_from_python);

    if (ret == 0 && decrypted_from_python) {
        printf("Decrypted by C: %s\n", decrypted_from_python);
        if (strcmp(expected_python_decryption, decrypted_from_python) == 0) {
            printf("C decryption of Python string: SUCCESSFUL\n");
        } else {
            printf("C decryption of Python string: FAILED\n");
            printf("Expected: %s\n", expected_python_decryption);
            printf("Got: %s\n", decrypted_from_python);
        }
        free(decrypted_from_python);
    } else {
        printf("C decryption of Python string FAILED (ret code: %d).\n", ret);
        if(decrypted_from_python) free(decrypted_from_python);
    }
    printf("Note: For the Python interop test to be meaningful, ensure 'python_encrypted_for_c' is an actual output from your Python script for the string '%s'.\n", expected_python_decryption);

    printf("\n--- Interoperability Test (C encrypts for others) ---\n");
    const char* c_msg_for_others = "Hello from C for other languages!";
    char* c_encrypted_for_others = NULL;
    ret = process_string_c('e', c_msg_for_others, &c_encrypted_for_others);
    if(ret == 0 && c_encrypted_for_others) {
        printf("C Encrypted for others: %s\n", c_encrypted_for_others);
        printf("Take this string and try to decrypt it using process_string('d', ...) in other languages.\n");
        free(c_encrypted_for_others);
    } else {
        printf("C Encryption for others FAILED (ret code: %d)\n", ret);
        if(c_encrypted_for_others) free(c_encrypted_for_others);
    }

    return 0;
}
