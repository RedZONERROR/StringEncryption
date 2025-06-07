package com.string.enc.application;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.view.View;
// No need to import Button, EditText, TextView explicitly if only accessed via binding
import android.widget.Toast;

import com.string.enc.StringCrypter; // Import the crypter class
import com.string.enc.application.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;
    public static final String PREFS_NAME = "StringEncAppPrefs";
    public static final String PREF_KEY_SECRET_KEY = "SecretKey";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Setup UI interaction
        setupUI();
        // Load saved key after UI is set up
        loadSavedKey();
    }

    private void loadSavedKey() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String savedKey = prefs.getString(PREF_KEY_SECRET_KEY, null);
        if (savedKey != null && !savedKey.isEmpty()) {
            binding.editTextKey.setText(savedKey);
            // Optionally, notify user that key was loaded
            // Toast.makeText(this, "Loaded saved key.", Toast.LENGTH_SHORT).show();
        }
    }

    private void saveKey(String key) {
        if (key == null || key.isEmpty()) return; // Don't save an empty key
        SharedPreferences.Editor editor = getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit();
        editor.putString(PREF_KEY_SECRET_KEY, key);
        editor.apply();
    }

    private void setupUI() {
        binding.buttonEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                handleEncryption();
            }
        });

        binding.buttonDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                handleDecryption();
            }
        });

        binding.textViewResult.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                copyResultToClipboard();
            }
        });
    }

    private void handleEncryption() {
        String data = binding.editTextData.getText().toString().trim();
        String key = binding.editTextKey.getText().toString(); // Key validation is handled by StringCrypter or below

        if (TextUtils.isEmpty(data)) {
            Toast.makeText(this, "Please enter text to encrypt.", Toast.LENGTH_SHORT).show();
            return;
        }
        // StringCrypter constructor will throw IllegalArgumentException if key is empty.
        // We can catch it or check beforehand for a friendlier UI message.
        if (TextUtils.isEmpty(key)) {
            Toast.makeText(this, "Please enter a secret key.", Toast.LENGTH_SHORT).show();
            binding.textViewResult.setText("Error: Secret key cannot be empty.");
            return;
        }

        try {
            StringCrypter crypter = new StringCrypter(key);
            String salt = StringCrypter.generateSalt(16); // 16 bytes -> 32 hex characters
            String dataWithSalt = salt + data;
            String encryptedResult = crypter.encrypt(dataWithSalt);
            binding.textViewResult.setText(encryptedResult);
            saveKey(key); // Save the successfully used key
            Toast.makeText(this, "Encryption successful! Key saved.", Toast.LENGTH_SHORT).show();
        } catch (IllegalArgumentException e) { // Catch key error from StringCrypter constructor
            binding.textViewResult.setText("Error: " + e.getMessage());
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            binding.textViewResult.setText("Error during encryption: " + e.getMessage());
            Toast.makeText(this, "Encryption failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void handleDecryption() {
        String encryptedData = binding.editTextData.getText().toString().trim();
        String key = binding.editTextKey.getText().toString();

        if (TextUtils.isEmpty(encryptedData)) {
            Toast.makeText(this, "Please enter text to decrypt.", Toast.LENGTH_SHORT).show();
            return;
        }
        if (TextUtils.isEmpty(key)) {
            Toast.makeText(this, "Please enter a secret key.", Toast.LENGTH_SHORT).show();
            binding.textViewResult.setText("Error: Secret key cannot be empty.");
            return;
        }

        try {
            StringCrypter crypter = new StringCrypter(key);
            String decryptedWithSalt = crypter.decrypt(encryptedData);

            if (decryptedWithSalt.length() < 32) { // Salt is 32 hex characters
                String errorMsg = "Error: Decrypted data too short to contain salt.";
                binding.textViewResult.setText(errorMsg);
                Toast.makeText(this, "Decryption failed: Invalid data format.", Toast.LENGTH_LONG).show();
                return;
            }
            String originalData = decryptedWithSalt.substring(32);
            binding.textViewResult.setText(originalData);
            saveKey(key); // Save the successfully used key
            Toast.makeText(this, "Decryption successful! Key saved.", Toast.LENGTH_SHORT).show();
        } catch (IllegalArgumentException e) { // Catch key error or Base64 error from StringCrypter
            binding.textViewResult.setText("Error: " + e.getMessage());
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        } catch (Exception e) { // Catches RuntimeExceptions from StringCrypter (e.g., wrapped Base64 error)
            binding.textViewResult.setText("Error during decryption: " + e.getMessage());
            Toast.makeText(this, "Decryption failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void copyResultToClipboard() {
        String resultText = binding.textViewResult.getText().toString();
        CharSequence hintText = binding.textViewResult.getHint();

        if (TextUtils.isEmpty(resultText) || (hintText != null && resultText.equals(hintText.toString())) || resultText.startsWith("Error:")) {
            Toast.makeText(this, "No valid result to copy.", Toast.LENGTH_SHORT).show();
            return;
        }

        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            ClipData clip = ClipData.newPlainText("Encrypted/Decrypted Text", resultText);
            clipboard.setPrimaryClip(clip);
            Toast.makeText(this, "Result copied to clipboard!", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "Failed to access clipboard service.", Toast.LENGTH_SHORT).show();
        }
    }
}