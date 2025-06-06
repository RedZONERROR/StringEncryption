# string_crypter.pl
use strict;
use warnings;
use MIME::Base64 qw(encode_base64 decode_base64);
use Encode qw(encode_utf8 decode_utf8); # For explicit UTF-8 handling

# For more cryptographically secure random bytes, one might use:
# use Bytes::Random::Secure qw(random_bytes); # If available
# For this example, we'll use a simpler approach for salt.

our $STATIC_KEY_PL = "test_key";
our $SALT_LENGTH_BYTES_PL = 16; # 16 bytes = 32 hex characters

sub generate_salt_pl {
    my $salt_bytes = "";
    for (1..$SALT_LENGTH_BYTES_PL) {
        $salt_bytes .= chr(int(rand(256)));
    }
    # Convert bytes to hex string
    return unpack('H*', $salt_bytes);
}

sub xor_strings_pl {
    my ($s1, $s2_key) = @_;
    return $s1 if length($s2_key) == 0;

    my $s1_len = length($s1);
    my $s2_len = length($s2_key);
    my $result = "";

    for (my $i = 0; $i < $s1_len; $i++) {
        $result .= chr(ord(substr($s1, $i, 1)) ^ ord(substr($s2_key, $i % $s2_len, 1)));
    }
    return $result;
}

sub encrypt_pl {
    my ($plaintext, $key_string) = @_;
    my $salt_hex = generate_salt_pl();
    
    # Prepend raw salt bytes (converted from hex) to UTF-8 encoded plaintext
    my $salt_raw = pack('H*', $salt_hex);
    my $plaintext_utf8 = encode_utf8($plaintext); # Ensure plaintext is UTF-8
    my $data_with_salt = $salt_raw . $plaintext_utf8;

    my $key_bytes = encode_utf8($key_string); # Ensure key is UTF-8

    my $xored_data = xor_strings_pl($data_with_salt, $key_bytes);
    my $encoded_base64 = encode_base64($xored_data, ""); # "" removes newlines
    return $encoded_base64;
}

sub decrypt_pl {
    my ($encrypted_data, $key_string) = @_;
    my $decoded_base64;
    eval {
        $decoded_base64 = decode_base64($encrypted_data);
    };
    if ($@) {
        print "Decryption error: Invalid Base64 string. $@\n";
        return undef;
    }

    my $key_bytes = encode_utf8($key_string); # Ensure key is UTF-8

    my $decrypted_with_salt = xor_strings_pl($decoded_base64, $key_bytes);

    my $salt_raw_len = $SALT_LENGTH_BYTES_PL; # Raw salt length
    if (length($decrypted_with_salt) < $salt_raw_len) {
        print "Decryption error: Decrypted data is too short to contain salt.\n";
        return undef;
    }

    # Salt is raw bytes, plaintext part needs UTF-8 decoding
    # my $salt_part = substr($decrypted_with_salt, 0, $salt_raw_len); # Not needed for output
    my $plaintext_part_utf8 = substr($decrypted_with_salt, $salt_raw_len);
    
    my $original_plaintext;
    eval {
        $original_plaintext = decode_utf8($plaintext_part_utf8, Encode::FB_CROAK);
    };
    if ($@) {
        print "Decryption error: Could not decode UTF-8 from decrypted data. $@\n";
        return undef; # Or handle error, e.g. return raw bytes
    }
    
    return $original_plaintext;
}

sub process_string_pl {
    my ($type, $data) = @_;
    my $key = $STATIC_KEY_PL;
    if ($type eq 'e') {
        return encrypt_pl($data, $key);
    } elsif ($type eq 'd') {
        return decrypt_pl($data, $key);
    } else {
        print "Error: Invalid type specified. Use 'e' for encrypt or 'd' for decrypt.\n";
        return undef;
    }
}

# Main test area
if ($0 eq __FILE__) {
    print "--- Perl String Encryption/Decryption Tests ---\n";

    my $original_text = "Hello from Perl!";
    print "Original Text: $original_text\n";

    my $encrypted_text = process_string_pl('e', $original_text);
    if (defined $encrypted_text) {
        print "Encrypted (Perl): $encrypted_text\n";

        my $decrypted_text = process_string_pl('d', $encrypted_text);
        if (defined $decrypted_text) {
            print "Decrypted (Perl): $decrypted_text\n";
            if ($decrypted_text eq $original_text) {
                print "Perl Encryption/Decryption Test: SUCCESSFUL\n";
            } else {
                print "Perl Encryption/Decryption Test: FAILED\n";
                print "Expected: $original_text, Got: $decrypted_text\n";
            }
        } else {
            print "Perl Decryption FAILED (result was undef).\n";
        }
    } else {
        print "Perl Encryption FAILED (result was undef).\n";
    }

    print "\n--- Interoperability Test (Perl decrypts Python) ---\
";
    # Example: String "Hello from Python for Perl!" encrypted by Python
    my $python_encrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q="; # Placeholder
    my $expected_python_decryption = "Hello from Python for Perl!"; # Placeholder

    print "Python Encrypted: $python_encrypted\n";
    my $decrypted_from_python = process_string_pl('d', $python_encrypted);
    if (defined $decrypted_from_python) {
        print "Decrypted by Perl: $decrypted_from_python\n";
        if ($decrypted_from_python eq $expected_python_decryption) {
            print "Perl decryption of Python string: SUCCESSFUL (with correct Python output)\n";
        } else {
            print "Perl decryption of Python string: FAILED or placeholder data used.\n";
            print "Expected: $expected_python_decryption, Got: $decrypted_from_python\n";
        }
    } else {
        print "Perl decryption of Python string FAILED (result was undef).\n";
    }
    print "Note: For the Python interop test to be meaningful, replace 'python_encrypted' with actual output from your Python script for the string '$expected_python_decryption'.\n";


    print "\n--- Interoperability Test (Perl encrypts for others) ---\n";
    my $perl_msg_for_others = "Hello from Perl for other languages!";
    my $perl_encrypted_for_others = process_string_pl('e', $perl_msg_for_others);
    if (defined $perl_encrypted_for_others) {
        print "Perl Encrypted for others (Original: '$perl_msg_for_others'): $perl_encrypted_for_others\n";
        print "Take this string and try to decrypt it using process_string('d', ...) in other languages.\n";
    } else {
        print "Perl encryption for others FAILED (result was undef).\n";
    }
}

1; # Required for 'use' and 'require'
