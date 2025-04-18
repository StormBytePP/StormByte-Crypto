# StormByte

StormByte is a comprehensive, cross-platform C++ library aimed at easing system programming, configuration management, logging, and database handling tasks. This library provides a unified API that abstracts away the complexities and inconsistencies of different platforms (Windows, Linux).

## Features

- **Encryption**: Robust encryption functionality, including AES, RSA, ECC, and DSA.
- **Hashing**: Support for SHA-256, SHA-512, Blake2s, and Blake2b.
- **Signing**: Signing and verification using DSA.
- **Compression**: Gzip and BZip2 compression and decompression.

## Table of Contents

- [Repository](#repository)
- [Installation](#installation)
- [Modules](#modules)
	- [Base](https://dev.stormbyte.org/StormByte)
	- [Config](https://dev.stormbyte.org/StormByte-Config)
	- **Crypto**
	- [Database](https://dev.stormbyte.org/StormByte-Database)
	- [Multimedia](https://dev.stormbyte.org/StormByte-Multimedia)
	- [Network](https://dev.stormbyte.org/StormByte-Network)
	- [System](https://dev.stormbyte.org/StormByte-System)
- [Contributing](#contributing)
- [License](#license)

## Modules

### Crypto

#### Overview

The `Crypto` module provides a wide range of cryptographic utilities, including hashing, encryption, signing, and compression. Below is a detailed breakdown of the functionality provided.

---

## Examples

### Hashing

#### SHA-256 Example
```cpp
#include <StormByte/crypto/hash/sha256.hxx>
#include <iostream>

using namespace StormByte::Crypto::Hash::SHA256;

int main() {
    const std::string input_data = "HashThisString";

    // Compute SHA-256 hash
    auto hash_result = Hash(input_data);
    if (hash_result.has_value()) {
        std::cout << "SHA-256 Hash: " << hash_result.value() << std::endl;
    } else {
        std::cerr << "Hashing failed!" << std::endl;
    }

    return 0;
}
```

#### SHA-512 Example
```cpp
#include <StormByte/crypto/hash/sha512.hxx>
#include <iostream>

using namespace StormByte::Crypto::Hash::SHA512;

int main() {
    const std::string input_data = "HashThisString";

    // Compute SHA-512 hash
    auto hash_result = Hash(input_data);
    if (hash_result.has_value()) {
        std::cout << "SHA-512 Hash: " << hash_result.value() << std::endl;
    } else {
        std::cerr << "Hashing failed!" << std::endl;
    }

    return 0;
}
```

#### Blake2s Example
```cpp
#include <StormByte/crypto/hash/blake2s.hxx>
#include <iostream>

using namespace StormByte::Crypto::Hash::Blake2s;

int main() {
    const std::string input_data = "HashThisString";

    // Compute Blake2s hash
    auto hash_result = Hash(input_data);
    if (hash_result.has_value()) {
        std::cout << "Blake2s Hash: " << hash_result.value() << std::endl;
    } else {
        std::cerr << "Hashing failed!" << std::endl;
    }

    return 0;
}
```

---

### Encryption

#### AES Example
```cpp
#include <StormByte/crypto/encryption/aes.hxx>
#include <iostream>

using namespace StormByte::Crypto::Encryption::AES;

int main() {
    const std::string password = "SecurePassword123!";
    const std::string original_data = "Confidential information.";

    // Encrypt the data
    auto encrypt_result = Encrypt(original_data, password);
    if (encrypt_result.has_value()) {
        auto encrypted_buffer = encrypt_result.value().get();
        std::cout << "Data encrypted successfully!" << std::endl;

        // Decrypt the data
        auto decrypt_result = Decrypt(encrypted_buffer, password);
        if (decrypt_result.has_value()) {
            auto decrypted_buffer = decrypt_result.value().get();
            std::string decrypted_data(reinterpret_cast<const char*>(decrypted_buffer.Data().data()), decrypted_buffer.Size());
            std::cout << "Decrypted Data: " << decrypted_data << std::endl;
        } else {
            std::cerr << "Decryption failed!" << std::endl;
        }
    } else {
        std::cerr << "Encryption failed!" << std::endl;
    }

    return 0;
}
```

#### RSA Example
```cpp
#include <StormByte/crypto/encryption/rsa.hxx>
#include <iostream>

using namespace StormByte::Crypto::Encryption::RSA;

int main() {
    const std::string message = "This is a test message.";
    const int key_strength = 2048;

    // Generate RSA key pair
    auto keypair_result = GenerateKeyPair(key_strength);
    if (keypair_result.has_value()) {
        auto [private_key, public_key] = keypair_result.value();

        // Encrypt the message
        auto encrypt_result = Encrypt(message, public_key);
        if (encrypt_result.has_value()) {
            auto encrypted_buffer = encrypt_result.value().get();
            std::cout << "Message encrypted successfully!" << std::endl;

            // Decrypt the message
            auto decrypt_result = Decrypt(encrypted_buffer, private_key);
            if (decrypt_result.has_value()) {
                std::cout << "Decrypted Message: " << decrypt_result.value() << std::endl;
            } else {
                std::cerr << "Decryption failed!" << std::endl;
            }
        } else {
            std::cerr << "Encryption failed!" << std::endl;
        }
    } else {
        std::cerr << "Key generation failed!" << std::endl;
    }

    return 0;
}
```

---

### Signing

#### DSA Example
```cpp
#include <StormByte/crypto/encryption/dsa.hxx>
#include <iostream>

using namespace StormByte::Crypto::Encryption::DSA;

int main() {
    const std::string message = "This is a test message.";
    const int key_strength = 2048;

    // Generate DSA key pair
    auto keypair_result = GenerateKeyPair(key_strength);
    if (keypair_result.has_value()) {
        auto [private_key, public_key] = keypair_result.value();

        // Sign the message
        auto sign_result = Sign(message, private_key);
        if (sign_result.has_value()) {
            std::string signature = sign_result.value();
            std::cout << "Message signed successfully!" << std::endl;

            // Verify the signature
            if (Verify(message, signature, public_key)) {
                std::cout << "Signature verified successfully!" << std::endl;
            } else {
                std::cerr << "Signature verification failed!" << std::endl;
            }
        } else {
            std::cerr << "Signing failed!" << std::endl;
        }
    } else {
        std::cerr << "Key generation failed!" << std::endl;
    }

    return 0;
}
```

---

### Compression

#### Gzip Example
```cpp
#include <StormByte/crypto/compressor/gzip.hxx>
#include <iostream>

using namespace StormByte::Crypto::Compressor::Gzip;

int main() {
    const std::string input_data = "Data to compress and decompress.";

    // Compress the data
    auto compress_result = Compress(input_data);
    if (compress_result.has_value()) {
        auto compressed_buffer = compress_result.value().get();
        std::cout << "Data compressed successfully!" << std::endl;

        // Decompress the data
        auto decompress_result = Decompress(compressed_buffer);
        if (decompress_result.has_value()) {
            auto decompressed_buffer = decompress_result.value().get();
            std::string decompressed_data(reinterpret_cast<const char*>(decompressed_buffer.Data().data()), decompressed_buffer.Size());
            std::cout << "Decompressed Data: " << decompressed_data << std::endl;
        } else {
            std::cerr << "Decompression failed!" << std::endl;
        }
    } else {
        std::cerr << "Compression failed!" << std::endl;
    }

    return 0;
}
```

#### BZip2 Example
```cpp
#include <StormByte/crypto/compressor/bzip2.hxx>
#include <iostream>

using namespace StormByte::Crypto::Compressor::BZip2;

int main() {
    const std::string input_data = "Data to compress and decompress.";

    // Compress the data
    auto compress_result = Compress(input_data);
    if (compress_result.has_value()) {
        auto compressed_buffer = compress_result.value().get();
        std::cout << "Data compressed successfully!" << std::endl;

        // Decompress the data
        auto decompress_result = Decompress(compressed_buffer, input_data.size());
        if (decompress_result.has_value()) {
            auto decompressed_buffer = decompress_result.value().get();
            std::string decompressed_data(reinterpret_cast<const char*>(decompressed_buffer.Data().data()), decompressed_buffer.Size());
            std::cout << "Decompressed Data: " << decompressed_data << std::endl;
        } else {
            std::cerr << "Decompression failed!" << std::endl;
        }
    } else {
        std::cerr << "Compression failed!" << std::endl;
    }

    return 0;
}
```

---

## Contributing

Contributions are welcome! Please follow the guidelines in the `CONTRIBUTING.md` file.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

