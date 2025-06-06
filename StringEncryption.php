<?php
class StringEncryption

{

    private $key;



    public function __construct($key)

    {

        if (empty($key)) {

            throw new InvalidArgumentException("Error : Key cannot.");

        }

        $this->key = $key;

    }



    public function encrypt($plaintext)

    {

        $ciphertext = '';

        $keyLength = strlen($this->key);

        

        for ($i = 0; $i < strlen($plaintext); $i++) {

            $ciphertext .= $plaintext[$i] ^ $this->key[$i % $keyLength];

        }

        

        return base64_encode($ciphertext);

    }



    public function decrypt($encryptedData)

    {

        $ciphertext = base64_decode($encryptedData);

        if ($ciphertext === false) {

            throw new Exception("Error : Decryption failed:");

        }



        $plaintext = '';

        $keyLength = strlen($this->key);



        for ($i = 0; $i < strlen($ciphertext); $i++) {

            $plaintext .= $ciphertext[$i] ^ $this->key[$i % $keyLength];

        }



        return $plaintext;

    }

}



function generateSalt($length = 16)

{

    return bin2hex(random_bytes($length));

}



function processString($type, $data)

{

    $staticKey = "test_key"; // Your static key
    $userIP = "";

    $dynamicKey = $userIP . $staticKey;



    $encryption = new StringEncryption($dynamicKey);



    try {

        if ($type === 'e') {

            $salt = generateSalt();

            $dataWithSalt = $salt . $data;

            return $encryption->encrypt($dataWithSalt);

        } elseif ($type === 'd') {

            $decryptedData = $encryption->decrypt($data);

            $salt = substr($decryptedData, 0, 32);

            $originalData = substr($decryptedData, 32);

            return $originalData;

        } else {

            return "Error: Invalid operation type";

        }

    } catch (Exception $e) {

    

        return "Error: "; // Return the error message

    }

}



//Example
$dataToEncrypt = "This is a secret message.";
echo "Original Data: " . $dataToEncrypt . "\n";

// Encrypt
$encryptedString = processString('e', $dataToEncrypt);
echo "Encrypted: " . $encryptedString . "\n";

// Decrypt
$decryptedString = processString('d', $encryptedString);
echo "Decrypted: " . $decryptedString . "\n";

// Verify
if ($dataToEncrypt === $decryptedString) {
    echo "Encryption and Decryption successful!\n";
} else {
    echo "Encryption and Decryption failed.\n";
}

// Test decryption of Java-encrypted string
$javaEncryptedString = "QFRAFW9SAEsWUBdFZl1RTxJVS0U+ClccRQAQQm5eABg8AB8YMEsDCxsIUz4+HQRZEgoBVA8jNVg=";
echo "\nAttempting to decrypt string from Java: " . $javaEncryptedString . "\n";
$decryptedFromJava = processString('d', $javaEncryptedString);
echo "Decrypted in PHP: " . $decryptedFromJava . "\n";

if ($decryptedFromJava === "Hello from Java for PHP!") {
    echo "Java to PHP decryption successful!\n";
} else {
    echo "Java to PHP decryption FAILED.\n";
    echo "Expected: Hello from Java for PHP!\n";
    echo "Got: " . $decryptedFromJava . "\n";
}



?>