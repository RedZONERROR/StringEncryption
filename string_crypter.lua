-- string_crypter.lua

local M = {} -- Module table

local STATIC_KEY_LUA = "test_key"
local SALT_LENGTH_BYTES_LUA = 16 -- 16 bytes = 32 hex characters

-- --- Base64 Implementation (Common pure Lua approach) ---
local b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function M.base64_encode(data)
    local result = ""
    local len = #data
    for i = 1, len, 3 do
        local c1 = string.byte(data, i)
        local c2 = string.byte(data, i + 1)
        local c3 = string.byte(data, i + 2)

        local b1 = bit32.rshift(c1, 2)
        local b2 = bit32.lshift(bit32.band(c1, 0x03), 4) + (c2 and bit32.rshift(c2, 4) or 0)
        local b3 = c2 and bit32.lshift(bit32.band(c2, 0x0F), 2) + (c3 and bit32.rshift(c3, 6) or 0) or 64
        local b4 = c3 and bit32.band(c3, 0x3F) or 64

        result = result .. string.sub(b64_chars, b1 + 1, b1 + 1)
                        .. string.sub(b64_chars, b2 + 1, b2 + 1)
                        .. (c2 and string.sub(b64_chars, b3 + 1, b3 + 1) or "=")
                        .. (c3 and string.sub(b64_chars, b4 + 1, b4 + 1) or "=")
    end
    return result
end

function M.base64_decode(data)
    data = string.gsub(data, "[^"..b64_chars.."=]", "")
    local result = ""
    local len = #data
    for i = 1, len, 4 do
        local b1 = string.find(b64_chars, string.sub(data, i, i), 1, true) - 1
        local b2 = string.find(b64_chars, string.sub(data, i + 1, i + 1), 1, true) - 1
        local b3_char = string.sub(data, i + 2, i + 2)
        local b4_char = string.sub(data, i + 3, i + 3)
        local b3 = (b3_char == "=") and 0 or string.find(b64_chars, b3_char, 1, true) - 1
        local b4 = (b4_char == "=") and 0 or string.find(b64_chars, b4_char, 1, true) - 1

        local c1 = bit32.lshift(b1, 2) + bit32.rshift(b2, 4)
        result = result .. string.char(c1)

        if b3_char ~= "=" then
            local c2 = bit32.lshift(bit32.band(b2, 0x0F), 4) + bit32.rshift(b3, 2)
            result = result .. string.char(c2)
        end
        if b4_char ~= "=" then
            local c3 = bit32.lshift(bit32.band(b3, 0x03), 6) + b4
            result = result .. string.char(c3)
        end
    end
    return result
end

-- --- Salt Generation ---
-- Note: math.random is not cryptographically secure.
local hex_chars_lua = "0123456789abcdef"
function M.generate_salt_lua()
    math.randomseed(os.time()) -- Seed for some variability
    local salt = ""
    for _ = 1, SALT_LENGTH_BYTES_LUA * 2 do
        salt = salt .. string.sub(hex_chars_lua, math.random(1, #hex_chars_lua), math.random(1, #hex_chars_lua))
    end
    return salt
end

-- --- XOR Operation ---
function M.xor_strings_lua(input, key)
    local output = ""
    local key_len = #key
    if key_len == 0 then return input end -- Avoid issues with empty key

    for i = 1, #input do
        local char_code_input = string.byte(input, i)
        local char_code_key = string.byte(key, (i - 1) % key_len + 1)
        output = output .. string.char(bit32.bxor(char_code_input, char_code_key))
    end
    return output
end

-- --- Encryption/Decryption Logic ---
function M.encrypt_lua(plaintext, key)
    local salt = M.generate_salt_lua()
    local data_with_salt = salt .. plaintext
    local xored_data = M.xor_strings_lua(data_with_salt, key)
    return M.base64_encode(xored_data)
end

function M.decrypt_lua(encrypted_data, key)
    local decoded_data = M.base64_decode(encrypted_data)
    local decrypted_with_salt = M.xor_strings_lua(decoded_data, key)
    
    local salt_hex_len = SALT_LENGTH_BYTES_LUA * 2
    if #decrypted_with_salt < salt_hex_len then
        return nil, "Decrypted data too short to contain salt"
    end
    return string.sub(decrypted_with_salt, salt_hex_len + 1)
end

-- --- Main Processing Function ---
function M.process_string_lua(op_type, data)
    local key = STATIC_KEY_LUA
    if op_type == 'e' then
        return M.encrypt_lua(data, key)
    elseif op_type == 'd' then
        local success, result_or_err = pcall(M.decrypt_lua, data, key)
        if success and result_or_err then
            return result_or_err
        elseif success and not result_or_err then -- Decrypt returned nil for valid reason (e.g. too short)
             return nil, "Decryption failed: data too short or invalid after XOR."
        else -- pcall caught an error from decrypt_lua (e.g. bad base64)
            return nil, "Decryption error: " .. tostring(result_or_err)
        end
    else
        return nil, "Invalid operation type: " .. tostring(op_type) .. ". Use 'e' or 'd'"
    end
end

-- --- Example Usage ---
local function run_lua_tests()
    print("--- Lua String Encryption/Decryption Tests ---")

    local original_text = "Hello from Lua!"
    print("Original Text: " .. original_text)

    local encrypted_text, err_enc = M.process_string_lua('e', original_text)
    if not encrypted_text then
        print("Lua Encryption FAILED: " .. err_enc)
        return
    end
    print("Encrypted (Lua): " .. encrypted_text)

    local decrypted_text, err_dec = M.process_string_lua('d', encrypted_text)
    if not decrypted_text then
        print("Lua Decryption FAILED: " .. err_dec)
        return
    end
    print("Decrypted (Lua): " .. decrypted_text)

    if decrypted_text == original_text then
        print("Lua Encryption/Decryption Test: SUCCESSFUL")
    else
        print("Lua Encryption/Decryption Test: FAILED")
        print("Expected: " .. original_text)
        print("Got: " .. decrypted_text)
    end

    print("\n--- Interoperability Test (Lua decrypts Python) ---")
    -- Example: String "Hello from Python for Lua!" encrypted by Python
    -- Python: StringCrypter().process_string('e', "Hello from Python for Lua!")
    -- Replace with actual Python output
    local python_encrypted = "NzM2MzMxMzEzNjY0NjEzMDYxMzQzNjY0NjIzNjYyMzQzNFN1Z2RjY2RjZWNkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2RjZWRlY2VjZGNlZGVjZWNkY2VkZWNlY2Q=" -- Placeholder
    local expected_python_decryption = "Hello from Python for Lua!" -- Placeholder

    print("Python Encrypted: " .. python_encrypted)
    local decrypted_from_python, err_py_dec = M.process_string_lua('d', python_encrypted)
    if decrypted_from_python then
        print("Decrypted by Lua: " .. decrypted_from_python)
        if decrypted_from_python == expected_python_decryption then
            print("Lua decryption of Python string: SUCCESSFUL (with correct Python output)")
        else
            print("Lua decryption of Python string: FAILED or placeholder data used.")
            print("Expected: " .. expected_python_decryption .. ", Got: " .. decrypted_from_python)
        end
    else
        print("Lua decryption of Python string FAILED: " .. (err_py_dec or "Unknown error"))
    end
    print("Note: For the Python interop test to be meaningful, replace 'python_encrypted' with actual output from your Python script for the string '"..expected_python_decryption.."'")

    print("\n--- Interoperability Test (Lua encrypts for others) ---")
    local lua_message_for_others = "Hello from Lua for other languages!"
    local lua_encrypted_for_others, err_lua_enc = M.process_string_lua('e', lua_message_for_others)
    if lua_encrypted_for_others then
        print("Lua Encrypted for others (Original: '"..lua_message_for_others.."'): " .. lua_encrypted_for_others)
        print("Take this string and try to decrypt it using process_string('d', ...) in other languages.")
    else
        print("Lua encryption for others FAILED: " .. (err_lua_enc or "Unknown error"))
    end
end

-- To run the tests:
run_lua_tests()

-- To use as a module:
-- return M
