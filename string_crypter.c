// string_crypter.c
#include "string_crypter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // For srand

// --- Configuration ---
static const char *STATIC_KEY_C = "test_key";
static const int SALT_LEN_BYTES_C = 16; // 16 bytes = 32 hex characters

// --- Base64 Implementation (Adapted from various public domain sources) ---
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static char *base64_encode_impl(const unsigned char *input, size_t len, size_t *output_len) {
    *output_len = 4 * ((len + 2) / 3);
    char *encoded_data = (char *)malloc(*output_len + 1); // +1 for null terminator
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < len;) {
        unsigned int octet_a = i < len ? input[i++] : 0;
        unsigned int octet_b = i < len ? input[i++] : 0;
        unsigned int octet_c = i < len ? input[i++] : 0;

        unsigned int triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    size_t mod_table[] = {0, 2, 1};
    for (size_t i = 0; i < mod_table[len % 3]; i++) {
        encoded_data[*output_len - 1 - i] = '=';
    }
    encoded_data[*output_len] = '\0';
    return encoded_data;
}

static unsigned char *base64_decode_impl(const char *input, size_t len, size_t *output_len) {
    if (len % 4 != 0) return NULL; 

    *output_len = len / 4 * 3;
    if (input[len - 1] == '=') (*output_len)--;
    if (input[len - 2] == '=') (*output_len)--;

    unsigned char *decoded_data = (unsigned char *)malloc(*output_len + 1);
    if (decoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < len;) {
        unsigned int sextet_a = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i++]) - base64_chars;
        unsigned int sextet_b = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i++]) - base64_chars;
        unsigned int sextet_c = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i++]) - base64_chars;
        unsigned int sextet_d = input[i] == '=' ? 0 & i++ : strchr(base64_chars, input[i++]) - base64_chars;

        unsigned int triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *output_len) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_len) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_len) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    decoded_data[*output_len] = '\0';
    return decoded_data;
}

// --- Salt Generation ---
static void generate_salt_c_impl(char salt_hex_buffer[SALT_LEN_BYTES_C * 2 + 1]) {
    const char hex_chars[] = "0123456789abcdef";
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    for (int i = 0; i < SALT_LEN_BYTES_C * 2; ++i) {
        salt_hex_buffer[i] = hex_chars[rand() % 16];
    }
    salt_hex_buffer[SALT_LEN_BYTES_C * 2] = '\0';
}

// --- XOR Operation ---
static void xor_string_c_impl(const char *input, size_t input_len, const char *key, char *output) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < input_len; ++i) {
        output[i] = input[i] ^ key[i % key_len];
    }
    output[input_len] = '\0';
}

// --- Main Processing Function ---
int process_string_c(char type, const char *data, char **result) {
    *result = NULL;
    const char *key = STATIC_KEY_C;

    if (type == 'e') {
        char salt_hex[SALT_LEN_BYTES_C * 2 + 1];
        generate_salt_c_impl(salt_hex);
        size_t data_len = strlen(data);
        size_t salted_data_len = (SALT_LEN_BYTES_C * 2) + data_len;
        char *salted_data = (char *)malloc(salted_data_len + 1);
        if (!salted_data) return -1;
        strcpy(salted_data, salt_hex);
        strcat(salted_data, data);
        salted_data[salted_data_len] = '\0';

        char *xored_data = (char *)malloc(salted_data_len + 1);
        if (!xored_data) {
            free(salted_data);
            return -1;
        }
        xor_string_c_impl(salted_data, salted_data_len, key, xored_data);
        free(salted_data);

        size_t b64_output_len;
        *result = base64_encode_impl((const unsigned char *)xored_data, salted_data_len, &b64_output_len);
        free(xored_data);
        if (!*result) return -1;
        return 0;

    } else if (type == 'd') {
        size_t decoded_data_len;
        unsigned char *decoded_data_unsigned = base64_decode_impl(data, strlen(data), &decoded_data_len);
        if (!decoded_data_unsigned) return -1;
        char *decoded_data = (char *)decoded_data_unsigned;

        char *decrypted_with_salt = (char *)malloc(decoded_data_len + 1);
        if (!decrypted_with_salt) {
            free(decoded_data);
            return -1;
        }
        xor_string_c_impl(decoded_data, decoded_data_len, key, decrypted_with_salt);
        free(decoded_data);

        if (decoded_data_len <= (SALT_LEN_BYTES_C * 2)) {
            free(decrypted_with_salt);
            *result = (char*)calloc(1,1); 
            if(!*result) return -1;
            return 0; 
        }

        *result = (char *)malloc(decoded_data_len - (SALT_LEN_BYTES_C * 2) + 1);
        if (!*result) {
            free(decrypted_with_salt);
            return -1;
        }
        strcpy(*result, decrypted_with_salt + (SALT_LEN_BYTES_C * 2));
        free(decrypted_with_salt);
        return 0;
    } else {
        return -1;
    }
}
