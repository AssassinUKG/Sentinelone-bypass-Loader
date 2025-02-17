#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>

// AES Key & IV Size
#define AES_KEY_SIZE  16  // 128-bit key
#define AES_IV_SIZE   12  // 96-bit IV
#define TAG_SIZE      16  // GCM Tag Size

void EncryptShellcode(const unsigned char* shellcode, size_t shellcodeSize, unsigned char* key, unsigned char* iv, unsigned char* encryptedShellcode, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    int outLen;
    EVP_EncryptUpdate(ctx, encryptedShellcode, &outLen, shellcode, shellcodeSize);

    int finalLen;
    EVP_EncryptFinal_ex(ctx, encryptedShellcode + outLen, &finalLen);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // 🔹 Replace this with your actual shellcode
    unsigned char shellcode[] = { /* PLACE YOUR RAW SHELLCODE HERE */ };
    size_t shellcodeSize = sizeof(shellcode);

    // Generate AES Key & IV
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    unsigned char tag[TAG_SIZE];

    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);

    // Allocate memory for the encrypted shellcode
    unsigned char* encryptedShellcode = new unsigned char[shellcodeSize];

    // Encrypt the shellcode
    EncryptShellcode(shellcode, shellcodeSize, key, iv, encryptedShellcode, tag);

    // Save the encrypted shellcode, key, IV, and tag to a file
    std::ofstream outFile("encrypted_shellcode.bin", std::ios::binary);
    outFile.write((char*)encryptedShellcode, shellcodeSize);
    outFile.write((char*)key, AES_KEY_SIZE);
    outFile.write((char*)iv, AES_IV_SIZE);
    outFile.write((char*)tag, TAG_SIZE);
    outFile.close();

    std::cout << "Shellcode successfully encrypted and saved!" << std::endl;

    delete[] encryptedShellcode;
    return 0;
}
