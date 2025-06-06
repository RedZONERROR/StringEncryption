import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Formatter; // For bytesToHex, an alternative

public class StringCrypter {

    private final String key;

    public StringCrypter(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Error: Key cannot be empty.");
        }
        this.key = key;
    }

    public String encrypt(String plaintext) {
        try {
            byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] keyBytes = this.key.getBytes(StandardCharsets.UTF_8);
            byte[] cipherBytes = new byte[plainBytes.length];
            int keyLength = keyBytes.length;

            for (int i = 0; i < plainBytes.length; i++) {
                cipherBytes[i] = (byte) (plainBytes[i] ^ keyBytes[i % keyLength]);
            }
            return Base64.getEncoder().encodeToString(cipherBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    public String decrypt(String encryptedData) {
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(encryptedData);
            byte[] keyBytes = this.key.getBytes(StandardCharsets.UTF_8);
            byte[] plainBytes = new byte[cipherBytes.length];
            int keyLength = keyBytes.length;

            for (int i = 0; i < cipherBytes.length; i++) {
                plainBytes[i] = (byte) (cipherBytes[i] ^ keyBytes[i % keyLength]);
            }
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) { 
             throw new RuntimeException("Error: Decryption failed. Invalid Base64 data.", e);
        } catch (Exception e) {
            throw new RuntimeException("Error: Decryption failed: " + e.getMessage(), e);
        }
    }

    public static String generateSalt(int lengthInBytes) {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[lengthInBytes];
        random.nextBytes(saltBytes);
        return bytesToHex(saltBytes);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static String processString(char type, String data) {
        String staticKey = "test_key"; 
        String userIP = ""; 
        String dynamicKey = userIP + staticKey;

        StringCrypter encryption = new StringCrypter(dynamicKey);

        try {
            if (type == 'e') {
                String salt = generateSalt(16); // 16 bytes -> 32 hex characters
                String dataWithSalt = salt + data;
                return encryption.encrypt(dataWithSalt);
            } else if (type == 'd') {
                String decryptedData = encryption.decrypt(data);
                if (decryptedData.length() < 32) { // Salt is 32 characters
                     throw new RuntimeException("Error: Decrypted data too short to contain salt.");
                }
                // String extractedSalt = decryptedData.substring(0, 32); // Salt not used after extraction in PHP
                return decryptedData.substring(32);
            } else {
                return "Error: Invalid operation type";
            }
        } catch (Exception e) {
            // Return error message similar to PHP's, but include exception message for more detail
            return "Error: " + e.getMessage(); 
        }
    }

    public static void main(String[] args) {
        String dataToEncrypt = "This is a secret message.";
        System.out.println("Original Data: " + dataToEncrypt);

        // Encrypt using Java
        String encryptedString = processString('e', dataToEncrypt);
        System.out.println("Encrypted (Java): " + encryptedString);

        // Decrypt using Java
        String decryptedString = processString('d', encryptedString);
        System.out.println("Decrypted (Java): " + decryptedString);

        // Verify
        if (dataToEncrypt.equals(decryptedString)) {
            System.out.println("Java Encryption and Decryption successful!");
        } else {
            System.out.println("Java Encryption and Decryption failed.");
            System.out.println("Expected: " + dataToEncrypt);
            System.out.println("Got: " + decryptedString);
        }
        
        System.out.println("\n--- Interoperability Notes ---");
        System.out.println("To test PHP encrypt -> Java decrypt:");
        System.out.println("1. Encrypt a string in PHP using processString('e', yourData).");
        System.out.println("2. Take the output and use it as input for Java's processString('d', phpEncryptedOutput).");
        
        System.out.println("\nTo test Java encrypt -> PHP decrypt:");
        String javaEncryptedForPHP = processString('e', "Hello from Java for PHP!");
        System.out.println("1. Java encrypted string: " + javaEncryptedForPHP);
        System.out.println("2. In PHP, use processString('d', '" + javaEncryptedForPHP + "') to decrypt.");
    }
}
