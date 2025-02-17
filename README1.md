1. aes_gcm_encrypt.cpp → Encrypts raw shellcode with AES-GCM.


2. aes_gcm_loader.cpp → Loads and executes the encrypted shellcode.


3. llvm_obfuscation_pass.cpp → Optional LLVM obfuscation pass to further increase stealth.



✅ How to Use These Files

🔹 Step 1: Compile the Encryption Tool

g++ aes_gcm_encrypt.cpp -o encryptor -lssl -lcrypto

🔹 Step 2: Run the Encryption Tool

./encryptor

Creates encrypted_shellcode.bin


🔹 Step 3: Compile the Loader

g++ aes_gcm_loader.cpp -o loader -lssl -lcrypto

🔹 Step 4: Run the Loader

./loader

Decrypts the shellcode and executes it undetectably.

