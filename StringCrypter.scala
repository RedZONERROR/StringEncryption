// StringCrypter.scala
import java.util.Base64
import java.security.SecureRandom
import java.nio.charset.StandardCharsets

object StringCrypter {
  private val STATIC_KEY_SCALA = "test_key"
  private val SALT_LENGTH_BYTES_SCALA = 16 // 16 bytes = 32 hex characters

  // Helper to convert Array[Byte] to Hex String
  private def bytesToHexString(bytes: Array[Byte]): String = {
    bytes.map(b => String.format("%02x", Byte.box(b))).mkString
  }

  def generateSaltScala(): String = {
    val random = new SecureRandom()
    val saltBytes = new Array[Byte](SALT_LENGTH_BYTES_SCALA)
    random.nextBytes(saltBytes)
    bytesToHexString(saltBytes)
  }

  def xorByteArraysScala(input: Array[Byte], key: Array[Byte]): Array[Byte] = {
    if (key.isEmpty) return input.clone() // Return a copy if key is empty
    val output = new Array[Byte](input.length)
    for (i <- input.indices) {
      output(i) = (input(i) ^ key(i % key.length)).toByte
    }
    output
  }

  def encryptScala(plaintext: String, keyString: String): Option[String] = {
    try {
      val saltHex = generateSaltScala()
      val dataWithSaltString = saltHex + plaintext

      val dataWithSaltBytes = dataWithSaltString.getBytes(StandardCharsets.UTF_8)
      val keyBytes = keyString.getBytes(StandardCharsets.UTF_8)

      val xoredBytes = xorByteArraysScala(dataWithSaltBytes, keyBytes)
      Some(Base64.getEncoder.encodeToString(xoredBytes))
    } catch {
      case e: Exception =>
        println(s"Encryption error: ${e.getMessage}")
        None
    }
  }

  def decryptScala(encryptedData: String, keyString: String): Option[String] = {
    try {
      val decodedBytes = Base64.getDecoder.decode(encryptedData)
      val keyBytes = keyString.getBytes(StandardCharsets.UTF_8)

      val decryptedWithSaltBytes = xorByteArraysScala(decodedBytes, keyBytes)
      val decryptedWithSaltString = new String(decryptedWithSaltBytes, StandardCharsets.UTF_8)

      val saltHexLen = SALT_LENGTH_BYTES_SCALA * 2
      if (decryptedWithSaltString.length < saltHexLen) {
        println("Decryption error: Decrypted data is too short to contain salt.")
        None
      } else {
        Some(decryptedWithSaltString.substring(saltHexLen))
      }
    } catch {
      case e: IllegalArgumentException => // Specific for Base64 issues
        println(s"Decryption error: Invalid Base64 string. ${e.getMessage}")
        None
      case e: Exception =>
        println(s"Decryption error: ${e.getMessage}")
        None
    }
  }

  def processStringScala(operationType: Char, data: String): Option[String] = {
    val key = STATIC_KEY_SCALA
    operationType match {
      case 'e' => encryptScala(data, key)
      case 'd' => decryptScala(data, key)
      case _ =>
        println("Error: Invalid type specified. Use 'e' for encrypt or 'd' for decrypt.")
        None
    }
  }

  def main(args: Array[String]): Unit = {
    println("--- Scala String Encryption/Decryption Tests ---")

    val originalText = "Hello from Scala!"
    println(s"Original Text: $originalText")

    processStringScala('e', originalText) match {
      case Some(encryptedText) =>
        println(s"Encrypted (Scala): $encryptedText")
        processStringScala('d', encryptedText) match {
          case Some(decryptedText) =>
            println(s"Decrypted (Scala): $decryptedText")
            if (decryptedText == originalText) {
              println("Scala Encryption/Decryption Test: SUCCESSFUL")
            } else {
              println("Scala Encryption/Decryption Test: FAILED")
              println(s"Expected: $originalText, Got: $decryptedText")
            }
          case None => println("Scala Decryption FAILED (result was None).")
        }
      case None => println("Scala Encryption FAILED (result was None).")
    }

    println("\n--- Interoperability Test (Scala decrypts Python) ---")
    // Example: String "Hello from Python for Scala!" encrypted by Python
    val pythonEncrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=" // Placeholder
    val expectedPythonDecryption = "Hello from Python for Scala!" // Placeholder

    println(s"Python Encrypted: $pythonEncrypted")
    processStringScala('d', pythonEncrypted) match {
      case Some(decryptedFromPython) =>
        println(s"Decrypted by Scala: $decryptedFromPython")
        if (decryptedFromPython == expectedPythonDecryption) {
          println("Scala decryption of Python string: SUCCESSFUL (with correct Python output)")
        } else {
          println("Scala decryption of Python string: FAILED or placeholder data used.")
          println(s"Expected: $expectedPythonDecryption, Got: $decryptedFromPython")
        }
      case None => println("Scala decryption of Python string FAILED (result was None).")
    }
    println(s"Note: For the Python interop test to be meaningful, replace 'pythonEncrypted' with actual output from your Python script for the string '$expectedPythonDecryption'.")

    println("\n--- Interoperability Test (Scala encrypts for others) ---")
    val scalaMsgForOthers = "Hello from Scala for other languages!"
    processStringScala('e', scalaMsgForOthers) match {
      case Some(scalaEncryptedForOthers) =>
        println(s"Scala Encrypted for others (Original: '$scalaMsgForOthers'): $scalaEncryptedForOthers")
        println("Take this string and try to decrypt it using process_string('d', ...) in other languages.")
      case None => println("Scala encryption for others FAILED (result was None).")
    }
  }
}
