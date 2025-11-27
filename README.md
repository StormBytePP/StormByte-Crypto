# StormByte

StormByte is a comprehensive, cross-platform C++ library aimed at easing system programming, configuration management, logging, and database handling tasks. This library provides a unified API that abstracts away the complexities and inconsistencies of different platforms (Windows, Linux).

## Features

- **Encryption**: Robust encryption functionality, including AES, RSA, ECC, and DSA.
- **Hashing**: Support for SHA-256, SHA-512, Blake2s, and Blake2b.
- **Signing**: Signing and verification using DSA, RSA, and ECDSA.
- **Compression**: Gzip and BZip2 compression and decompression.
- **Key Exchange**: Secure shared secret generation using ECDH.

## Table of Contents

- [Repository](#repository)
- [Installation](#installation)
- [Modules](#modules)
    - [Base](https://dev.stormbyte.org/StormByte)
    - [Config](https://dev.stormbyte.org/StormByte-Config)
    - **Crypto**
    - [Database](https://dev.stormbyte.org/StormByte-Database)
	- [Memory](https://dev.stormbyte.org/StormByte-Memory)
    - [Multimedia](https://dev.stormbyte.org/StormByte-Multimedia)
    - [Network](https://dev.stormbyte.org/StormByte-Network)
    - [System](https://dev.stormbyte.org/StormByte-System)
- [Contributing](#contributing)
- [License](#license)

## Modules

### Crypto

#### Overview

The `Crypto` module provides a wide range of cryptographic utilities, including hashing, encryption, signing, compression, and key exchange. Below is a detailed breakdown of the functionality provided.

---

## Examples

### Hashing

#### SHA-256 Example
```cpp
#include <StormByte/crypto/hasher.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string input_data = "HashThisString";

    // Create a SHA-256 hasher
    Hasher sha256(Algorithm::Hash::SHA256);

    // Compute the hash
    auto hash_result = sha256.Hash(input_data);
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
#include <StormByte/crypto/hasher.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string input_data = "HashThisString";

    // Create a SHA-512 hasher
    Hasher sha512(Algorithm::Hash::SHA512);

    // Compute the hash
    auto hash_result = sha512.Hash(input_data);
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
#include <StormByte/crypto/hasher.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string input_data = "HashThisString";

    // Create a Blake2s hasher
    Hasher blake2s(Algorithm::Hash::Blake2s);

    // Compute the hash
    auto hash_result = blake2s.Hash(input_data);
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
#include <StormByte/crypto/symmetric.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string password = "SecurePassword123!";
    const std::string original_data = "Confidential information.";

    // Create an AES instance
    Symmetric aes(Algorithm::Symmetric::AES, password);

    // Encrypt the data
    auto encrypt_result = aes.Encrypt(original_data);
    if (encrypt_result.has_value()) {
        auto encrypted_buffer = encrypt_result.value();
        std::cout << "Data encrypted successfully!" << std::endl;

        // Decrypt the data
        auto decrypt_result = aes.Decrypt(encrypted_buffer);
        if (decrypt_result.has_value()) {
            std::string decrypted_data(reinterpret_cast<const char*>(decrypt_result.value().Data().data()), decrypt_result.value().Size());
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
#include <StormByte/crypto/asymetric.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string message = "This is a test message.";
    const int key_strength = 2048;

    // Generate RSA key pair
    auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
    if (keypair_result.has_value()) {
        Asymmetric rsa(Algorithm::Asymmetric::RSA, keypair_result.value());

        // Encrypt the message
        auto encrypt_result = rsa.Encrypt(message);
        if (encrypt_result.has_value()) {
            auto encrypted_buffer = encrypt_result.value();
            std::cout << "Message encrypted successfully!" << std::endl;

            // Decrypt the message
            auto decrypt_result = rsa.Decrypt(encrypted_buffer);
            if (decrypt_result.has_value()) {
                std::string decrypted_message(reinterpret_cast<const char*>(decrypt_result.value().Data().data()), decrypt_result.value().Size());
                std::cout << "Decrypted Message: " << decrypted_message << std::endl;
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
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::DSA, key_Strength);
    if (keypair_result.has_value()) {
        Signer dsa(keypair_result.value());

        // Sign the message
        auto sign_result = dsa.Sign(message);
        if (sign_result.has_value()) {
            std::string signature = sign_result.value();
            std::cout << "Message signed successfully!" << std::endl;

            // Verify the signature
            if (dsa.Verify(message, signature)) {
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

#### ECDSA Example
```cpp
#include <StormByte/crypto/signer.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string message = "This is a test message.";
    const std::string curve_name = "secp256r1";

    // Generate an ECDSA key pair
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::ECDSA, curve_name);
    if (keypair_result.has_value()) {
        Signer ecdsa(Algorithm::Sign::ECDSA, keypair_result.value());

        // Sign the message
        auto sign_result = ecdsa.Sign(message);
        if (sign_result.has_value()) {
            std::string signature = sign_result.value();
            std::cout << "Message signed successfully!" << std::endl;

            // Verify the signature
            if (ecdsa.Verify(message, signature)) {
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
#include <StormByte/crypto/compressor.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string input_data = "Data to compress and decompress.";

    // Create a Gzip compressor
    Compressor gzip(Algorithm::Compress::Gzip);

    // Compress the data
    auto compress_result = gzip.Compress(input_data);
    if (compress_result.has_value()) {
        auto compressed_buffer = compress_result.value();
        std::cout << "Data compressed successfully!" << std::endl;

        // Decompress the data
        auto decompress_result = gzip.Decompress(compressed_buffer);
        if (decompress_result.has_value()) {
            std::string decompressed_data(reinterpret_cast<const char*>(decompress_result.value().Data().data()), decompress_result.value().Size());
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

### Key Exchange

#### ECDH Example
```cpp
#include <StormByte/crypto/secret.hxx>
#include <iostream>

using namespace StormByte::Crypto;

int main() {
    const std::string curve_name = "secp256r1";

    // Generate key pairs for server and client
    auto server_keypair = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);
    auto client_keypair = KeyPair::Generate(Algorithm::SecretShare::ECDH, curve_name);

    if (server_keypair.has_value() && client_keypair.has_value()) {
        Secret server_secret(Algorithm::SecretShare::ECDH, server_keypair.value());
        Secret client_secret(Algorithm::SecretShare::ECDH, client_keypair.value());

        // Exchange public keys
        server_secret.PeerPublicKey(client_keypair->PublicKey());
        client_secret.PeerPublicKey(server_keypair->PublicKey());

        // Derive shared secrets
        auto server_shared_secret = server_secret.Content();
        auto client_shared_secret = client_secret.Content();

        if (server_shared_secret.has_value() && client_shared_secret.has_value()) {
            std::cout << "Shared secret derived successfully!" << std::endl;
            std::cout << "Server Shared Secret: " << server_shared_secret.value() << std::endl;
            std::cout << "Client Shared Secret: " << client_shared_secret.value() << std::endl;
        } else {
            std::cerr << "Failed to derive shared secret!" << std::endl;
        }
    } else {
        std::cerr << "Key pair generation failed!" << std::endl;
    }

    return 0;
}
```

---

## Contributing

Contributions are welcome! Please follow the guidelines in the `CONTRIBUTING.md` file.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

