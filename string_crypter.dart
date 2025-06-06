// string_crypter.dart
import 'dart:convert'; // For base64 and utf8
import 'dart:math';   // For Random
import 'dart:typed_data'; // For Uint8List

const String staticKeyDart = "test_key";
const int saltLengthBytesDart = 16; // 16 bytes = 32 hex characters

String _bytesToHexString(Uint8List bytes) {
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
}

String generateSaltDart() {
  final random = Random.secure();
  final saltBytes = Uint8List(saltLengthBytesDart);
  for (int i = 0; i < saltLengthBytesDart; i++) {
    saltBytes[i] = random.nextInt(256);
  }
  return _bytesToHexString(saltBytes);
}

Uint8List xorByteArraysDart(Uint8List input, Uint8List key) {
  final output = Uint8List(input.length);
  if (key.isEmpty) return Uint8List.fromList(input); // Return a copy if key is empty
  for (int i = 0; i < input.length; i++) {
    output[i] = input[i] ^ key[i % key.length];
  }
  return output;
}

String encryptDart(String plaintext, String keyString) {
  final saltHex = generateSaltDart();
  final dataWithSaltString = saltHex + plaintext;

  final dataWithSaltBytes = utf8.encode(dataWithSaltString);
  final keyBytes = utf8.encode(keyString);

  final xoredBytes = xorByteArraysDart(Uint8List.fromList(dataWithSaltBytes), Uint8List.fromList(keyBytes));
  return base64.encode(xoredBytes);
}

String? decryptDart(String encryptedData, String keyString) {
  try {
    final decodedBytes = base64.decode(encryptedData);
    final keyBytes = utf8.encode(keyString);

    final decryptedWithSaltBytes = xorByteArraysDart(decodedBytes, Uint8List.fromList(keyBytes));
    // Convert the entire byte array to string first
    final decryptedWithSaltString = utf8.decode(decryptedWithSaltBytes);

    final saltHexLen = saltLengthBytesDart * 2;
    if (decryptedWithSaltString.length < saltHexLen) {
      print("Decryption error: Decrypted data is too short to contain salt.");
      return null;
    }
    // Then extract the substring after the salt
    return decryptedWithSaltString.substring(saltHexLen);
  } catch (e) {
    print("Decryption error: ${e.toString()}");
    return null;
  }
}

String? processStringDart(String type, String data) {
  final key = staticKeyDart;
  switch (type) {
    case 'e':
      return encryptDart(data, key);
    case 'd':
      return decryptDart(data, key);
    default:
      print("Error: Invalid type specified. Use 'e' for encrypt or 'd' for decrypt.");
      return null;
  }
}

void main() {
  print("--- Dart String Encryption/Decryption Tests ---");

  final originalText = "Hello from Dart!";
  print("Original Text: $originalText");

  final encryptedText = processStringDart('e', originalText);
  if (encryptedText != null) {
    print("Encrypted (Dart): $encryptedText");

    final decryptedText = processStringDart('d', encryptedText);
    if (decryptedText != null) {
      print("Decrypted (Dart): $decryptedText");
      if (decryptedText == originalText) {
        print("Dart Encryption/Decryption Test: SUCCESSFUL");
      } else {
        print("Dart Encryption/Decryption Test: FAILED");
        print("Expected: $originalText, Got: $decryptedText");
      }
    } else {
      print("Dart Decryption FAILED (result was null).");
    }
  } else {
    print("Dart Encryption FAILED (result was null).");
  }

  print("\n--- Interoperability Test (Dart decrypts Python) ---");
  // Example: String "Hello from Python for Dart!" encrypted by Python
  // Python: StringCrypter().process_string('e', "Hello from Python for Dart!")
  final pythonEncrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q="; // Placeholder
  final expectedPythonDecryption = "Hello from Python for Dart!"; // Placeholder

  print("Python Encrypted: $pythonEncrypted");
  final decryptedFromPython = processStringDart('d', pythonEncrypted);
  if (decryptedFromPython != null) {
    print("Decrypted by Dart: $decryptedFromPython");
    if (decryptedFromPython == expectedPythonDecryption) {
      print("Dart decryption of Python string: SUCCESSFUL (with correct Python output)");
    } else {
      print("Dart decryption of Python string: FAILED or placeholder data used.");
      print("Expected: $expectedPythonDecryption, Got: $decryptedFromPython");
    }
  } else {
    print("Dart decryption of Python string FAILED (result was null).");
  }
  print("Note: For the Python interop test to be meaningful, replace 'pythonEncrypted' with actual output from your Python script for the string '$expectedPythonDecryption'.");


  print("\n--- Interoperability Test (Dart encrypts for others) ---");
  final dartMsgForOthers = "Hello from Dart for other languages!";
  final dartEncryptedForOthers = processStringDart('e', dartMsgForOthers);
  if (dartEncryptedForOthers != null) {
    print("Dart Encrypted for others (Original: '$dartMsgForOthers'): $dartEncryptedForOthers");
    print("Take this string and try to decrypt it using process_string('d', ...) in other languages.");
  } else {
    print("Dart encryption for others FAILED (result was null).");
  }
}
