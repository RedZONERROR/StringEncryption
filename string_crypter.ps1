# string_crypter.ps1

function ConvertTo-Hex([byte[]]$bytes) {
    return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

function ConvertFrom-Hex([string]$hexString) {
    $bytes = New-Object byte[] ($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    return $bytes
}

function Generate-SaltPs {
    $saltBytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($saltBytes)
    return ConvertTo-Hex $saltBytes
}

function Xor-Bytes([byte[]]$inputBytes, [byte[]]$keyBytes) {
    if ($keyBytes.Length -eq 0) { return $inputBytes }
    $outputBytes = New-Object byte[] $inputBytes.Length
    for ($i = 0; $i -lt $inputBytes.Length; $i++) {
        $outputBytes[$i] = $inputBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    return $outputBytes
}

function Encrypt-StringPs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$plaintext,
        [string]$keyString = "test_key"
    )
    try {
        $saltHex = Generate-SaltPs
        $dataWithSaltString = $saltHex + $plaintext

        $dataWithSaltBytes = [System.Text.Encoding]::UTF8.GetBytes($dataWithSaltString)
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyString)

        $xoredBytes = Xor-Bytes $dataWithSaltBytes $keyBytes
        return [System.Convert]::ToBase64String($xoredBytes)
    } catch {
        Write-Error "Encryption error: $($_.Exception.Message)"
        return $null
    }
}

function Decrypt-StringPs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$encryptedData,
        [string]$keyString = "test_key"
    )
    try {
        $decodedBytes = [System.Convert]::FromBase64String($encryptedData)
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyString)

        $decryptedWithSaltBytes = Xor-Bytes $decodedBytes $keyBytes
        $decryptedWithSaltString = [System.Text.Encoding]::UTF8.GetString($decryptedWithSaltBytes)

        $saltHexLen = 32 # 16 bytes * 2 hex chars/byte
        if ($decryptedWithSaltString.Length -lt $saltHexLen) {
            Write-Error "Decryption error: Decrypted data is too short to contain salt."
            return $null
        }
        return $decryptedWithSaltString.Substring($saltHexLen)
    } catch {
        Write-Error "Decryption error: $($_.Exception.Message)"
        return $null
    }
}

function Process-StringPs {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("e", "d")]
        [char]$operationType,

        [Parameter(Mandatory=$true)]
        [string]$data
    )
    $staticKey = "test_key"
    if ($operationType -eq 'e') {
        return Encrypt-StringPs -plaintext $data -keyString $staticKey
    } elseif ($operationType -eq 'd') {
        return Decrypt-StringPs -encryptedData $data -keyString $staticKey
    } else {
        Write-Error "Invalid operation type. Use 'e' for encrypt or 'd' for decrypt."
        return $null
    }
}

# --- Test Section ---
Write-Host "--- PowerShell String Encryption/Decryption Tests ---"

$originalText = "Hello from PowerShell! With Ümlauts and €uro signs."
Write-Host "Original Text: $originalText"

$encrypted = Process-StringPs -operationType 'e' -data $originalText
if ($encrypted) {
    Write-Host "Encrypted (PowerShell): $encrypted"
    $decrypted = Process-StringPs -operationType 'd' -data $encrypted
    if ($decrypted) {
        Write-Host "Decrypted (PowerShell): $decrypted"
        if ($decrypted -eq $originalText) {
            Write-Host "PowerShell Encryption/Decryption Test: SUCCESSFUL" -ForegroundColor Green
        } else {
            Write-Host "PowerShell Encryption/Decryption Test: FAILED" -ForegroundColor Red
            Write-Host "Expected: $originalText"
            Write-Host "Got:      $decrypted"
        }
    } else {
         Write-Host "PowerShell Decryption FAILED." -ForegroundColor Red
    }
} else {
    Write-Host "PowerShell Encryption FAILED." -ForegroundColor Red
}

Write-Host "`n--- Interoperability Test (PowerShell decrypts Python example) ---"
# This is an example string "Hello from Python for PS!" encrypted by a compatible Python script.
# Python code: process_string('e', "Hello from Python for PS!")
# Output (example): NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=
# The salt part will vary, so this exact string is just a placeholder structure.
# You'd need to generate one from your Python (or other language) script.
$pythonEncrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=" # Placeholder
$expectedPythonDecryption = "Hello from Python for PS!" # Placeholder

Write-Host "Python Encrypted (Placeholder): $pythonEncrypted"
$decryptedFromPython = Process-StringPs -operationType 'd' -data $pythonEncrypted
if ($decryptedFromPython) {
    Write-Host "Decrypted by PowerShell: $decryptedFromPython"
    if ($decryptedFromPython -eq $expectedPythonDecryption) {
        Write-Host "PowerShell decryption of Python string: SUCCESSFUL (if placeholder matches actual)" -ForegroundColor Green
    } else {
        Write-Host "PowerShell decryption of Python string: FAILED or placeholder data used." -ForegroundColor Yellow
        Write-Host "Expected: $expectedPythonDecryption"
        Write-Host "Got:      $decryptedFromPython"
    }
} else {
    Write-Host "PowerShell decryption of Python string FAILED." -ForegroundColor Red
}
Write-Host "Note: For the interop test to be meaningful, replace 'pythonEncrypted' with actual output from another language."

Write-Host "`n--- Interoperability Test (PowerShell encrypts for others) ---"
$psMsgForOthers = "Hello from PowerShell for other languages!"
$psEncryptedForOthers = Process-StringPs -operationType 'e' -data $psMsgForOthers
if ($psEncryptedForOthers) {
    Write-Host "PowerShell Encrypted for others (Original: '$psMsgForOthers'): $psEncryptedForOthers"
    Write-Host "Take this string and try to decrypt it using other language scripts."
} else {
    Write-Host "PowerShell encryption for others FAILED." -ForegroundColor Red
}
