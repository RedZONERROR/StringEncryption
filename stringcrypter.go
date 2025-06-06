package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
)

const (
	staticKeyGo     = "test_key"
	saltLengthBytesGo = 16 // 16 bytes = 32 hex characters
)

// generateSaltGo creates a random salt of saltLengthBytesGo and returns it as a hex-encoded string.
func generateSaltGo() (string, error) {
	saltBytes := make([]byte, saltLengthBytesGo)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	return hex.EncodeToString(saltBytes), nil
}

// xorStringsGo performs XOR operation between input bytes and key bytes.
func xorStringsGo(input []byte, key []byte) []byte {
	output := make([]byte, len(input))
	keyLen := len(key)
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%keyLen]
	}
	return output
}

// EncryptGo encrypts plaintext: prepends salt, XORs with key, then Base64 encodes.
func EncryptGo(plaintext string, key string) (string, error) {
	salt, err := generateSaltGo()
	if err != nil {
		return "", err
	}
	dataWithSalt := salt + plaintext
	xoredData := xorStringsGo([]byte(dataWithSalt), []byte(key))
	return base64.StdEncoding.EncodeToString(xoredData), nil
}

// DecryptGo decrypts Base64 encoded data: decodes, XORs with key, then removes salt.
func DecryptGo(encryptedData string, key string) (string, error) {
	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	decryptedWithSalt := xorStringsGo(decodedData, []byte(key))
	if len(decryptedWithSalt) < saltLengthBytesGo*2 {
		return "", fmt.Errorf("decrypted data too short to contain salt")
	}
	return string(decryptedWithSalt[saltLengthBytesGo*2:]), nil
}

// ProcessStringGo is the main processing function.
func ProcessStringGo(opType rune, data string) (string, error) {
	key := staticKeyGo
	switch opType {
	case 'e':
		return EncryptGo(data, key)
	case 'd':
		return DecryptGo(data, key)
	default:
		return "", fmt.Errorf("invalid operation type: %c. Use 'e' or 'd'", opType)
	}
}

func main() {
	fmt.Println("--- Go String Encryption/Decryption Tests ---")

	originalText := "Hello from Go!"
	fmt.Printf("Original Text: %s\n", originalText)

	encryptedText, err := ProcessStringGo('e', originalText)
	if err != nil {
		log.Fatalf("Go Encryption FAILED: %v", err)
	}
	fmt.Printf("Encrypted (Go): %s\n", encryptedText)

	decryptedText, err := ProcessStringGo('d', encryptedText)
	if err != nil {
		log.Fatalf("Go Decryption FAILED: %v", err)
	}
	fmt.Printf("Decrypted (Go): %s\n", decryptedText)

	if decryptedText == originalText {
		fmt.Println("Go Encryption/Decryption Test: SUCCESSFUL")
	} else {
		fmt.Printf("Go Encryption/Decryption Test: FAILED\nExpected: %s\nGot: %s\n", originalText, decryptedText)
	}

	fmt.Println("\n--- Interoperability Test (Go decrypts Python) ---")
	// Example: String "Hello from Python for Go!" encrypted by Python
	// Python: StringCrypter().process_string('e', "Hello from Python for Go!")
	// Replace with actual Python output
	pythonEncrypted := "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=" // Placeholder
	expectedPythonDecryption := "Hello from Python for Go!" // Placeholder

	fmt.Printf("Python Encrypted: %s\n", pythonEncrypted)
	decryptedFromPython, err := ProcessStringGo('d', pythonEncrypted)
	if err != nil {
		fmt.Printf("Go decryption of Python string FAILED: %v\n", err)
	} else {
		fmt.Printf("Decrypted by Go: %s\n", decryptedFromPython)
		if decryptedFromPython == expectedPythonDecryption {
			fmt.Println("Go decryption of Python string: SUCCESSFUL (with correct Python output)")
		} else {
			fmt.Println("Go decryption of Python string: FAILED or placeholder data used.")
			fmt.Printf("Expected: %s, Got: %s\n", expectedPythonDecryption, decryptedFromPython)
		}
	}
	fmt.Println("Note: For the Python interop test to be meaningful, replace 'pythonEncrypted' with actual output from your Python script.")

	fmt.Println("\n--- Interoperability Test (Go encrypts for others) ---")
	goEncryptedForOthers, err := ProcessStringGo('e', "Hello from Go for other languages!")
	if err != nil {
		log.Fatalf("Go encryption for others FAILED: %v", err)
	}
	fmt.Printf("Go Encrypted for others: %s\n", goEncryptedForOthers)
	fmt.Println("Take this string and try to decrypt it using process_string('d', ...) in other languages.")
}
