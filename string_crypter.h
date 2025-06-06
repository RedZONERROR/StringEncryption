// string_crypter.h
#ifndef STRING_CRYPTER_H
#define STRING_CRYPTER_H

#include <stddef.h> // For size_t

/**
 * Processes the input string for encryption or decryption.
 *
 * The function allocates memory for the result string, which must be freed
 * by the caller using free().
 *
 * @param type 'e' for encrypt, 'd' for decrypt.
 * @param data The input string data to process.
 * @param result A pointer to a char pointer where the address of the
 *               dynamically allocated result string will be stored.
 * @return 0 on success, -1 on error (e.g., memory allocation failure, invalid type).
 *         If an error occurs, *result will be set to NULL.
 */
int process_string_c(char type, const char *data, char **result);

#endif // STRING_CRYPTER_H
