using System;
using System.Text;
using System.Security.Cryptography; // For RandomNumberGenerator

public class StringCrypter
{
    private readonly byte[] _key;

    public StringCrypter(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new ArgumentException("Error: Key cannot be empty.");
        }
        _key = Encoding.UTF8.GetBytes(key);
    }

    public string Encrypt(string plaintext)
    {
        try
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] cipherBytes = new byte[plainBytes.Length];
            int keyLength = _key.Length;

            for (int i = 0; i < plainBytes.Length; i++)
            {
                cipherBytes[i] = (byte)(plainBytes[i] ^ _key[i % keyLength]);
            }
            return Convert.ToBase64String(cipherBytes);
        }
        catch (Exception e)
        {
            throw new ApplicationException($"Encryption failed: {e.Message}", e);
        }
    }

    public string Decrypt(string encryptedData)
    {
        try
        {
            byte[] cipherBytes = Convert.FromBase64String(encryptedData);
            byte[] plainBytes = new byte[cipherBytes.Length];
            int keyLength = _key.Length;

            for (int i = 0; i < cipherBytes.Length; i++)
            {
                plainBytes[i] = (byte)(cipherBytes[i] ^ _key[i % keyLength]);
            }
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (FormatException e)
        {
            throw new ApplicationException("Error: Decryption failed. Invalid Base64 data.", e);
        }
        catch (Exception e)
        {
            throw new ApplicationException($"Error: Decryption failed: {e.Message}", e);
        }
    }

    public static string GenerateSalt(int lengthInBytes = 16)
    {
        byte[] saltBytes = new byte[lengthInBytes];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }
        // Convert bytes to hex string
        StringBuilder hex = new StringBuilder(saltBytes.Length * 2);
        foreach (byte b in saltBytes)
        {
            hex.AppendFormat("{0:x2}", b);
        }
        return hex.ToString();
    }

    public static string ProcessString(char type, string data)
    {
        string staticKey = "test_key";
        string userIP = ""; // Kept for consistency
        string dynamicKey = userIP + staticKey;

        StringCrypter encryption = new StringCrypter(dynamicKey);

        try
        {
            if (type == 'e')
            {
                string salt = GenerateSalt(16); // 16 bytes -> 32 hex characters
                string dataWithSalt = salt + data;
                return encryption.Encrypt(dataWithSalt);
            }
            else if (type == 'd')
            {
                string decryptedData = encryption.Decrypt(data);
                if (decryptedData.Length < 32) // Salt is 32 characters
                {
                    throw new ApplicationException("Error: Decrypted data too short to contain salt.");
                }
                // string extractedSalt = decryptedData.Substring(0, 32); // Salt not used after extraction
                return decryptedData.Substring(32);
            }
            else
            {
                return "Error: Invalid operation type";
            }
        }
        catch (Exception e)
        {
            return $"Error: {e.Message}";
        }
    }

    public static void Main(string[] args)
    {
        string dataToEncrypt = "This is a secret message.";
        Console.WriteLine($"Original Data: {dataToEncrypt}");

        // Encrypt using C#
        string encryptedString = ProcessString('e', dataToEncrypt);
        Console.WriteLine($"Encrypted (C#): {encryptedString}");

        // Decrypt using C#
        string decryptedString = ProcessString('d', encryptedString);
        Console.WriteLine($"Decrypted (C#): {decryptedString}");

        // Verify
        if (dataToEncrypt.Equals(decryptedString))
        {
            Console.WriteLine("C# Encryption and Decryption successful!");
        }
        else
        {
            Console.WriteLine("C# Encryption and Decryption failed.");
            Console.WriteLine($"Expected: {dataToEncrypt}");
            Console.WriteLine($"Got: {decryptedString}");
        }

        Console.WriteLine("\n--- Interoperability Test (C# decrypts Python) ---");
        // String "Hello from Python for PHP/Java!" encrypted by Python:
        // W1dAFGgJAUwVUEtBZ1pQHUNcFhI8XAEYQARCRWlaXU0gDRoHfwIWWRVFABE8GQANVAgWBywKAhxaWGkUVGy1LNTEkSjkVKQpE
        string pythonEncrypted = "W1dAFGgJAUwVUEtBZ1pQHUNcFhI8XAEYQARCRWlaXU0gDRoHfwIWWRVFABE8GQANVAgWBywKAhxaWGkUVGy1LNTEkSjkVKQpE";
        string expectedPythonDecryption = "Hello from Python for PHP/Java!";
        Console.WriteLine($"Python Encrypted: {pythonEncrypted}");
        string decryptedFromPython = ProcessString('d', pythonEncrypted);
        Console.WriteLine($"Decrypted by C#: {decryptedFromPython}");
        if (expectedPythonDecryption.Equals(decryptedFromPython))
        {
            Console.WriteLine("C# decryption of Python string successful!");
        }
        else
        {
            Console.WriteLine("C# decryption of Python string FAILED.");
        }


        Console.WriteLine("\n--- Interoperability Test (C# encrypts for others) ---");
        string csEncryptedForOthers = ProcessString('e', "Hello from C# for other languages!");
        Console.WriteLine($"C# Encrypted for others: {csEncryptedForOthers}");
        Console.WriteLine("Take this string and try to decrypt it using process_string('d', ...) in Python or other languages.");
    }
}
