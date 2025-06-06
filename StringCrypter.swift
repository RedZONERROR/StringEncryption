// StringCrypter.swift
import Foundation

let STATIC_KEY_SWIFT = "test_key"
let SALT_LENGTH_BYTES_SWIFT = 16 // 16 bytes = 32 hex characters

// Helper to convert Data to Hex String
extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

// Helper to convert Hex String to Data
extension String {
    func hexDecodedData() -> Data? {
        var data = Data(capacity: self.count / 2)
        var index = self.startIndex
        while index < self.endIndex {
            let nextIndex = self.index(index, offsetBy: 2)
            guard nextIndex <= self.endIndex,
                  let b = UInt8(self[index..<nextIndex], radix: 16) else {
                // print("Error: Non-hex character found or odd-length string")
                return nil // Or handle error appropriately
            }
            data.append(b)
            index = nextIndex
        }
        return data
    }
}


func generateSaltSwift() -> String {
    var saltBytes = Data(count: SALT_LENGTH_BYTES_SWIFT)
    _ = saltBytes.withUnsafeMutableBytes { mutableBytes in
        SecRandomCopyBytes(kSecRandomDefault, SALT_LENGTH_BYTES_SWIFT, mutableBytes.baseAddress!)
    }
    return saltBytes.hexEncodedString()
}

func xorDataSwift(input: Data, key: Data) -> Data {
    var output = Data(count: input.count)
    guard !key.isEmpty else { return input }
    for i in 0..<input.count {
        output[i] = input[i] ^ key[i % key.count]
    }
    return output
}

func encryptSwift(plaintext: String, keyString: String) -> String? {
    let saltHex = generateSaltSwift()
    guard let plaintextData = (saltHex + plaintext).data(using: .utf8),
          let keyData = keyString.data(using: .utf8) else {
        return nil
    }

    let xoredData = xorDataSwift(input: plaintextData, key: keyData)
    return xoredData.base64EncodedString()
}

func decryptSwift(encryptedData: String, keyString: String) -> String? {
    guard let decodedData = Data(base64Encoded: encryptedData),
          let keyData = keyString.data(using: .utf8) else {
        // print("Error: Invalid Base64 string or key string.")
        return nil
    }

    let decryptedWithSaltData = xorDataSwift(input: decodedData, key: keyData)
    guard let decryptedWithSaltString = String(data: decryptedWithSaltData, encoding: .utf8) else {
        // print("Error: Could not convert decrypted data to UTF-8 string.")
        return nil
    }

    let saltHexLen = SALT_LENGTH_BYTES_SWIFT * 2
    guard decryptedWithSaltString.count >= saltHexLen else {
        // print("Error: Decrypted data too short to contain salt.")
        return nil
    }
    let saltEndIndex = decryptedWithSaltString.index(decryptedWithSaltString.startIndex, offsetBy: saltHexLen)
    return String(decryptedWithSaltString[saltEndIndex...])
}

func processStringSwift(type: Character, data: String) -> String? {
    let key = STATIC_KEY_SWIFT
    switch type {
    case "e":
        return encryptSwift(plaintext: data, keyString: key)
    case "d":
        return decryptSwift(encryptedData: data, keyString: key)
    default:
        print("Error: Invalid type specified. Use 'e' for encrypt or 'd' for decrypt.")
        return nil
    }
}

// Main test area
func runSwiftTests() {
    print("--- Swift String Encryption/Decryption Tests ---")

    let originalText = "Hello from Swift!"
    print("Original Text: \(originalText)")

    if let encryptedText = processStringSwift(type: "e", data: originalText) {
        print("Encrypted (Swift): \(encryptedText)")

        if let decryptedText = processStringSwift(type: "d", data: encryptedText) {
            print("Decrypted (Swift): \(decryptedText)")
            if decryptedText == originalText {
                print("Swift Encryption/Decryption Test: SUCCESSFUL")
            } else {
                print("Swift Encryption/Decryption Test: FAILED")
                print("Expected: \(originalText), Got: \(decryptedText)")
            }
        } else {
            print("Swift Decryption FAILED (result was nil).")
        }
    } else {
        print("Swift Encryption FAILED (result was nil).")
    }

    print("\n--- Interoperability Test (Swift decrypts Python) ---")
    // Example: String "Hello from Python for Swift!" encrypted by Python
    let pythonEncrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=" // Placeholder
    let expectedPythonDecryption = "Hello from Python for Swift!" // Placeholder

    print("Python Encrypted: \(pythonEncrypted)")
    if let decryptedFromPython = processStringSwift(type: "d", data: pythonEncrypted) {
        print("Decrypted by Swift: \(decryptedFromPython)")
        if decryptedFromPython == expectedPythonDecryption {
            print("Swift decryption of Python string: SUCCESSFUL (with correct Python output)")
        } else {
            print("Swift decryption of Python string: FAILED or placeholder data used.")
            print("Expected: \(expectedPythonDecryption), Got: \(decryptedFromPython)")
        }
    } else {
        print("Swift decryption of Python string FAILED (result was nil).")
    }
     print("Note: For the Python interop test to be meaningful, replace 'pythonEncrypted' with actual output from your Python script for the string '\(expectedPythonDecryption)'.")


    print("\n--- Interoperability Test (Swift encrypts for others) ---")
    let swiftMsgForOthers = "Hello from Swift for other languages!"
    if let swiftEncryptedForOthers = processStringSwift(type: "e", data: swiftMsgForOthers) {
        print("Swift Encrypted for others (Original: '\(swiftMsgForOthers)'): \(swiftEncryptedForOthers)")
        print("Take this string and try to decrypt it using process_string('d', ...) in other languages.")
    } else {
        print("Swift encryption for others FAILED (result was nil).")
    }
}

// To run these tests, you would typically call runSwiftTests()
// In a Swift playground, the output will appear automatically.
// For a command-line tool, you'd have a main.swift that calls this.
 runSwiftTests()
