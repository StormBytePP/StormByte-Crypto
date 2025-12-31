# StormByte
![Linux](https://img.shields.io/badge/Linux-Supported-1793D1?logo=linux&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Supported-0078D6?logo=windows&logoColor=white)
![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C?logo=c%2B%2B&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.12+-064F8C?logo=cmake&logoColor=white)
![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)
![Status](https://img.shields.io/badge/Status-Active-success)
[![Compile & Test](https://github.com/StormBytePP/StormByte-Crypto/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/StormBytePP/StormByte-Crypto/actions/workflows/build.yml)

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
	- [Buffer](https://dev.stormbyte.org/StormByte-Buffer)
    - [Config](https://dev.stormbyte.org/StormByte-Config)
    - **Crypto**
    - [Database](https://dev.stormbyte.org/StormByte-Database)
	- [Logger](https://github.com/StormBytePP/StormByte-Logger.git)
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

### Overview

The examples below show concise, copy-pastable usage patterns used by the unit tests in `test/`.

Common patterns used in the examples and tests:

- Convenience/block APIs: accept `std::span<const std::byte>` or `Buffer::ReadOnly` and write into `Buffer::WriteOnly` (return `bool` success).
- Streaming APIs: accept a `Buffer::Consumer` and return a `Buffer::Consumer` for output (producer/consumer handoff).
- Key generation: you can either use the generic factory functions (e.g. `KeyPair::Create(...)`) or call the concrete type generators directly (e.g. `KeyPair::ECC::Generate(...)`, `KeyPair::RSA::Generate(...)`).

Code snippets below are intentionally short; see `test/` for full, real-world examples.

### Compression

Compressors are created via the `StormByte::Crypto::Compressor::Create` factory and follow a Buffer-centric API.

- Create a compressor:

```cpp
auto compressor = StormByte::Crypto::Compressor::Create(StormByte::Crypto::Compressor::Type::Zlib, /*level*/5);
```

- Block (whole-message) compression/decompression:

```cpp
// input: std::span<std::byte> or Buffer::ReadOnly
StormByte::Buffer::WriteOnly out;
bool ok = compressor->DoCompress(std::span<const std::byte>(data.ptr, data.len), out);
// or use the convenience overloads that accept Buffer::ReadOnly
```

- Streaming (Producer/Consumer): pass a `Buffer::Consumer` to `Compress` and receive a `Buffer::Consumer` with compressed output.

```cpp
StormByte::Buffer::Producer inputProducer;
auto inputConsumer = inputProducer.Consumer();
auto compressedConsumer = compressor->Compress(inputConsumer);
// write into inputProducer (or a FIFO/Producer) and close it; read compressed data from compressedConsumer
```

The implementation uses `libbzip2` for Bzip2 and Crypto++ filters for Zlib/Gzip where available.

### Symmetric (Crypter)

Symmetric encryption utilities live under `StormByte::Crypto::Crypter`. Use the `Crypter::Create` factory for symmetric types and provide a password/key. The returned object follows the buffer-centric API (block + streaming).

Examples (AES-CBC / AES-GCM):

```cpp
// create a symmetric crypter (AES-CBC) with a password
auto sym = StormByte::Crypto::Crypter::Create(StormByte::Crypto::Crypter::Type::AES, "password-or-key");
StormByte::Buffer::WriteOnly out;
// encrypt a span (block API)
bool ok = sym->Encrypt(std::span<const std::byte>(data.ptr, data.len), out);

// AES-GCM (authenticated)
auto gcm = StormByte::Crypto::Crypter::Create(StormByte::Crypto::Crypter::Type::AES_GCM, "32-byte-key-or-password");
ok = gcm->Encrypt(std::span<const std::byte>(data.ptr, data.len), out);
// Decrypt returns bool and writes to a WriteOnly; authentication failures will be reported by a false return
```

Streaming encryption mirrors compressors: pass a `Buffer::Consumer` to `Encrypt` and read from the returned `Buffer::Consumer`.

### Asymmetric (KeyPair + Asymmetric crypter)

Key pairs live under `StormByte::Crypto::KeyPair` and can be created via the per-type `Generate(...)` static methods (recommended) or via the generic factory `KeyPair::Create(Type, bits)`.

The asymmetric crypters are available under `StormByte::Crypto::Crypter` (asymmetric variants) and can be created by passing a `KeyPair` pointer to the asymmetric `Create` overload.

Examples (RSA):

```cpp
// generate an RSA keypair directly
auto kp = StormByte::Crypto::KeyPair::RSA::Generate(2048);

// create an asymmetric crypter using the generated keypair
auto rsa = StormByte::Crypto::Crypter::Create(StormByte::Crypto::Crypter::Type::RSA, kp);

// encrypt/decrypt using block APIs (span -> WriteOnly)
StormByte::Buffer::WriteOnly out;
bool ok = rsa->Encrypt(std::span<const std::byte>(data.ptr, data.len), out);
```

Examples (ECC / ECDH note):

```cpp
// elliptic-curve keypair generation
auto kp1 = StormByte::Crypto::KeyPair::ECC::Generate();
auto kp2 = StormByte::Crypto::KeyPair::ECC::Generate();

// For EC-based key agreement use `StormByte::Crypto::Secret` helpers (see Secret section) rather than Encrypt/Decrypt for symmetric key derivation
```

### Hash

Hashers are provided via `StormByte::Crypto::Hasher::Create` (see headers) and operate on Buffer types or spans.

Examples:

```cpp
auto hasher = StormByte::Crypto::Hasher::Create(StormByte::Crypto::Hasher::Type::SHA256);
StormByte::Buffer::WriteOnly out;
// Hash a span or use the Buffer overloads
bool ok = hasher->Hash(std::span<const std::byte>(data.ptr, data.len), out);
// For streaming/hash-on-the-fly pass a Buffer::Consumer and receive a Buffer::Consumer
```

### Sign

Signers are created with `StormByte::Crypto::Signer::Create` (factory overloads accept a `KeyPair` pointer or reference). APIs are Buffer-oriented.

```cpp
auto kp = StormByte::Crypto::KeyPair::Create(StormByte::Crypto::KeyPair::Type::ECDSA, /*bits*/256);
auto signer = StormByte::Crypto::Signer::Create(StormByte::Crypto::Signer::Type::ECDSA, kp);
StormByte::Buffer::WriteOnly sigOut;
bool ok = signer->Sign(std::span<const std::byte>(data.ptr, data.len), sigOut);
// Verify using Verify(...) overloads that accept Buffer::ReadOnly or Consumer
```

### Secret Share (Key agreement)

The `StormByte::Crypto::Secret` namespace provides key-agreement helpers (ECDH, X25519). Construct a secret helper with a `KeyPair` pointer (factory `Secret::Create` exists) or call a concrete secret class if available.

Example (ECDH):

```cpp
// generate EC keypairs
auto a = StormByte::Crypto::KeyPair::ECC::Generate();
auto b = StormByte::Crypto::KeyPair::ECC::Generate();

// create an ECDH secret helper using the keypair
auto sA = StormByte::Crypto::Secret::Create(StormByte::Crypto::Secret::Type::ECDH, a);
auto sharedA = sA->Share(b->PublicKey());
// sharedA is std::optional<std::string> containing the derived secret on success
```

Example (X25519):

```cpp
auto a = StormByte::Crypto::KeyPair::X25519::Generate();
auto b = StormByte::Crypto::KeyPair::X25519::Generate();
auto sA = StormByte::Crypto::Secret::Create(StormByte::Crypto::Secret::Type::X25519, a);
auto shared = sA->Share(b->PublicKey());
```

For streaming examples, inspect `test/compressors/*_test.cxx`, `test/aes_test.cxx`, `test/ecdsa_test.cxx`, and friends — they demonstrate both convenience and streaming workflows used above.


### Public API (high-level)

The public API is organized into small logical namespaces (e.g. `Hasher`, `Compressor`, `Crypter`, `KeyPair`, `Signer`, `Secret`) and uses factory functions and buffer-oriented interfaces. Refer to the `lib/public/StormByte/crypto` headers for the authoritative API.

- Factories

  - `StormByte::Crypto::Hasher::Create(Type)` -> returns a `Hasher::Generic::PointerType` (smart pointer).
  - `StormByte::Crypto::Compressor::Create(Type, level)` -> returns a `Compressor::Generic::PointerType`.
  - `StormByte::Crypto::KeyPair::Create(Type, bits)` -> returns a `KeyPair::Generic::PointerType`.
  - `StormByte::Crypto::Signer::Create(Type, keypair)` -> returns a `Signer::Generic::PointerType`.

- Buffer-centric APIs

  - Block/whole-message functions accept `std::span<const std::byte>` or `Buffer::ReadOnly` and write output into a `Buffer::WriteOnly`. They return `bool` to indicate success.
  - Streaming functions accept a `Buffer::Consumer` and return a `Buffer::Consumer` for the produced output. The streaming stages run in detached threads and use `Producer`/`Consumer` for handoff.

- Examples (compressed summary)

  - Compressor (create + compress a buffer):

    ```cpp
    auto c = StormByte::Crypto::Compressor::Create(StormByte::Crypto::Compressor::Type::Zlib, 5);
    StormByte::Buffer::WriteOnly out;
    bool ok = c->DoCompress(std::span<const std::byte>(data.ptr, data.len), out);
    ```

  - Streaming compressor:

    ```cpp
    StormByte::Buffer::Producer p;
    auto input = p.Consumer();
    auto outConsumer = c->Compress(input);
    // write to p and close; read from outConsumer
    ```

  - Signer/Hasher/Crypter follow the same patterns: factory -> call `Sign`/`Hash`/`Encrypt` on spans or pass Consumers for streaming.

See the headers in `lib/public/StormByte/crypto` and the tests in `test/` for concrete usage patterns.

## Contributing

Contributions are welcome! Please follow the guidelines in the `CONTRIBUTING.md` file.

## License

This project is licensed under the LGPL v3 License. See the `LICENSE` file for details.
