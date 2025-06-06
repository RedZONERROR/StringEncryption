// StringCrypter.kt
import java.util.Base64
import java.security.SecureRandom
import java.nio.charset.StandardCharsets

const val STATIC_KEY_KT = "test_key"
const val SALT_LENGTH_BYTES_KT = 16 // 16 bytes = 32 hex characters

// Extension function to convert ByteArray to Hex String
fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

fun generateSaltKt(): String {
    val random = SecureRandom()
    val saltBytes = ByteArray(SALT_LENGTH_BYTES_KT)
    random.nextBytes(saltBytes)
    return saltBytes.toHexString()
}

fun xorByteArrayKt(input: ByteArray, key: ByteArray): ByteArray {
    val output = ByteArray(input.size)
    if (key.isEmpty()) return input.copyOf() // Return a copy if key is empty
    for (i in input.indices) {
        output[i] = (input[i].toInt() xor key[i % key.size].toInt()).toByte()
    }
    return output
}

fun encryptKt(plaintext: String, keyString: String): String {
    val saltHex = generateSaltKt()
    val dataWithSaltString = saltHex + plaintext

    val dataWithSaltBytes = dataWithSaltString.toByteArray(StandardCharsets.UTF_8)
    val keyBytes = keyString.toByteArray(StandardCharsets.UTF_8)

    val xoredBytes = xorByteArrayKt(dataWithSaltBytes, keyBytes)
    return Base64.getEncoder().encodeToString(xoredBytes)
}

fun decryptKt(encryptedData: String, keyString: String): String? {
    return try {
        val decodedBytes = Base64.getDecoder().decode(encryptedData)
        val keyBytes = keyString.toByteArray(StandardCharsets.UTF_8)

        val decryptedWithSaltBytes = xorByteArrayKt(decodedBytes, keyBytes)
        // Convert the entire byte array to string first
        val decryptedWithSaltString = String(decryptedWithSaltBytes, StandardCharsets.UTF_8)

        val saltHexLen = SALT_LENGTH_BYTES_KT * 2
        if (decryptedWithSaltString.length < saltHexLen) {
            println("Decryption error: Decrypted data is too short to contain salt.")
            return null
        }
        // Then extract the substring after the salt
        decryptedWithSaltString.substring(saltHexLen)
    } catch (e: IllegalArgumentException) {
        println("Decryption error: Invalid Base64 string. ${e.message}")
        null
    } catch (e: Exception) {
        println("Decryption error: ${e.message}")
        null
    }
}

fun processStringKt(type: Char, data: String): String? {
    val key = STATIC_KEY_KT
    return when (type) {
        'e' -> encryptKt(data, key)
        'd' -> decryptKt(data, key)
        else -> {
            println("Error: Invalid type specified. Use 'e' for encrypt or 'd' for decrypt.")
            null
        }
    }
}

fun main() {
    println("--- Kotlin String Encryption/Decryption Tests ---")

    val originalText = "Hello from Kotlin!"
    println("Original Text: $originalText")

    val encryptedText = processStringKt('e', originalText)
    if (encryptedText != null) {
        println("Encrypted (Kotlin): $encryptedText")

        val decryptedText = processStringKt('d', encryptedText)
        if (decryptedText != null) {
            println("Decrypted (Kotlin): $decryptedText")
            if (decryptedText == originalText) {
                println("Kotlin Encryption/Decryption Test: SUCCESSFUL")
            } else {
                println("Kotlin Encryption/Decryption Test: FAILED")
                println("Expected: $originalText, Got: $decryptedText")
            }
        } else {
            println("Kotlin Decryption FAILED (result was null).")
        }
    } else {
        println("Kotlin Encryption FAILED (result was null).")
    }

    println("\n--- Interoperability Test (Kotlin decrypts Python) ---")
    // Example: String "Hello from Python for Kotlin!" encrypted by Python
    // Python: StringCrypter().process_string('e', "Hello from Python for Kotlin!")
    val pythonEncrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=" // Placeholder
    val expectedPythonDecryption = "Hello from Python for Kotlin!" // Placeholder

    println("Python Encrypted: $pythonEncrypted")
    val decryptedFromPython = processStringKt('d', pythonEncrypted)
    if (decryptedFromPython != null) {
        println("Decrypted by Kotlin: $decryptedFromPython")
        if (decryptedFromPython == expectedPythonDecryption) {
            println("Kotlin decryption of Python string: SUCCESSFUL (with correct Python output)")
        } else {
            println("Kotlin decryption of Python string: FAILED or placeholder data used.")
            println("Expected: $expectedPythonDecryption, Got: $decryptedFromPython")
        }
    } else {
        println("Kotlin decryption of Python string FAILED (result was null).")
    }
    println("Note: For the Python interop test to be meaningful, replace 'pythonEncrypted' with actual output from your Python script for the string '$expectedPythonDecryption'.")

    println("\n--- Interoperability Test (Kotlin encrypts for others) ---")
    val kotlinMsgForOthers = "Hello from Kotlin for other languages!"
    val kotlinEncryptedForOthers = processStringKt('e', kotlinMsgForOthers)
    if (kotlinEncryptedForOthers != null) {
        println("Kotlin Encrypted for others (Original: '$kotlinMsgForOthers'): $kotlinEncryptedForOthers")
        println("Take this string and try to decrypt it using process_string('d', ...) in other languages.")
    } else {
        println("Kotlin encryption for others FAILED (result was null).")
    }
}
