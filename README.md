# instask2

# **Key Management System (KMS)**

## **Overview**

This document provides an overview of the Key Management System (KMS) that supports the secure management of cryptographic keys. It provides methods for generating symmetric keys (AES), asymmetric key pairs (RSA), and Diffie-Hellman key pairs for secure key exchange. It also includes functionality for key revocation to prevent unauthorized access in case of key compromise.

## **Core Features**

The KMS offers the following features:

- **Symmetric Key Management (AES)**:
  - Generates and stores 256-bit AES keys.
  - Performs AES encryption and decryption using CBC mode and PKCS7 padding for secure data handling.

- **Asymmetric Key Management (RSA)**:
  - Generates RSA 2048-bit key pairs (public/private).
  - Encrypts and decrypts data using RSA with PKCS1v15 padding.

- **Diffie-Hellman Key Exchange**:
  - Generates Diffie-Hellman key pairs for secure key exchange.
  
- **Key Revocation**:
  - Supports key revocation to remove compromised keys from the system.

## **System Architecture**

The KMS is structured into the following key components:

1. **Symmetric Key Management (AES)**:
   - AES-256 keys are used to encrypt and decrypt data.
   - AES keys are stored in memory and can be used for secure data transmission.

2. **Asymmetric Key Management (RSA)**:
   - RSA 2048-bit key pairs (private and public) are generated for each user to encrypt and decrypt sensitive data.

3. **Diffie-Hellman Key Exchange**:
   - Diffie-Hellman key exchange ensures that session keys are securely generated and shared between parties, ensuring forward secrecy.

4. **Key Revocation**:
   - The KMS includes a mechanism to revoke keys, ensuring that compromised keys cannot be used for decryption or encryption.

## **Implementation**

### **Key Management System (KMS) Class**

The KMS is implemented in the `KeyMgmtSys` class with the following methods:

- **`gen_aes_key(key_id)`**: Generates and stores a 256-bit AES key for a given `key_id`.
- **`gen_rsa_pair(user_id)`**: Generates and stores a RSA 2048-bit key pair for a given `user_id`.
- **`aes_encrypt(key_id, text)`**: Encrypts a given `text` using the AES key identified by `key_id`.
- **`aes_decrypt(key_id, enc_data)`**: Decrypts a given ciphertext `enc_data` using the AES key identified by `key_id`.
- **`rsa_encrypt(user_id, text)`**: Encrypts a given `text` using the public key associated with `user_id`.
- **`rsa_decrypt(user_id, enc_data)`**: Decrypts a given ciphertext `enc_data` using the private key associated with `user_id`.
- **`dh_keygen()`**: Generates a Diffie-Hellman private and public key pair for secure key exchange.
- **`revoke_key(key_id)`**: Revokes a key (either symmetric or asymmetric) identified by `key_id`, deleting it from the system.

### **Libraries Used**

- **cryptography.hazmat.primitives**: Implements the cryptographic algorithms for AES, RSA, Diffie-Hellman, and padding.
- **os**: Used for secure random byte generation.
- **base64**: For encoding and decoding binary data to/from text.

## **Security Considerations**

The system is designed to protect data using industry-standard cryptographic techniques:

- **AES Encryption**: Provides secure symmetric encryption to protect sensitive data.
- **RSA Encryption**: Ensures the confidentiality of messages using public-key cryptography.
- **Diffie-Hellman Key Exchange**: Ensures that session keys remain secure even if long-term keys are compromised.
- **Key Revocation**: Ensures that compromised keys are immediately revoked to prevent unauthorized access.

## **Test Results**

The following functionalities were tested:

1. **AES Encryption/Decryption**: Confirmed AES encryption and decryption work correctly.
2. **RSA Encryption/Decryption**: Successfully tested RSA encryption and decryption with generated key pairs.
3. **Diffie-Hellman Key Exchange**: Successfully generated Diffie-Hellman public/private key pairs.
4. **Key Revocation**: Verified that keys are properly revoked and cannot be used for decryption after revocation.

## **Conclusion**

This Key Management System provides secure key generation, storage, and management using AES, RSA, and Diffie-Hellman algorithms. It includes key revocation functionality to mitigate risks associated with key compromise, offering a robust solution for secure data transmission and storage.

