# PiSecure

- A camera app with on-board, instant, on-capture cryptocurrency style encryption using ChaCha20 without any key storage (on demand key derivation using BCrypt KDF). Image stored as json. Goal was to eliminate the middle man i.e storage/transmission vulnerability window.

# Specifics
- BCrypt salt: 16 bytes (salt tied to username.json)
- Nonce: 24 bytes
- Derived key: 32 bytes

# Limitations: 
1. Crypto style encryption with no recovery of the image if user loses password.
2. Large overhead. Encrypted file is ~53 times unencrypted image (Albeit PiSecure provides lossless encryption and decryption)
3. Processing time: Tested at roughly ~4 seconds for a ~2mb JPG. Tested on i5 - 11400h.
