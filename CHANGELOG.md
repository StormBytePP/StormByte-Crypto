# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Switched Bzip2 build system to StormByte-BuildMaster for consistency with other bundled components

## [1.0.0] - 2026-08-20

Initial public release of **StormByte-Crypto**: a modern C++23 cryptography library built on top of StormByte-Buffer and Crypto++, providing compression, symmetric and asymmetric encryption, hashing, key-pair management, key agreement, digital signatures and secure secret storage for the StormByte ecosystem.

### Added

#### Compression
- **Bzip2** compressor with configurable level (1–9), one-shot and streaming APIs
- **Zlib** compressor with configurable level, one-shot and streaming APIs
- Unified `Compressor::Generic` interface with `Buffer::Consumer` pipelines

#### Symmetric encryption
- **AES** (CBC mode)
- **AES-GCM** (authenticated encryption)
- **Camellia** (CBC mode)
- **ChaCha20-Poly1305** (AEAD)
- **Serpent** (CBC mode)
- **Twofish** (CBC mode)
- Password-based key derivation via PBKDF2-HMAC-SHA256
- One-shot and streaming encrypt/decrypt through `Buffer::Consumer` / `Producer`

#### Asymmetric encryption
- **ECC** (ECIES over secp curves)
- **RSA** (OAEP-SHA)
- Hybrid envelope strategy (public-key wrapped AES-GCM session key) alongside native PK encryption
- Automatic detection of hybrid vs native payload on decrypt
- Strategy selection (`Native` / `Hybrid`) on encrypt

#### Hashing
- **BLAKE2b** and **BLAKE2s**
- **SHA-256** and **SHA-512**
- **SHA3-256** and **SHA3-512**
- Hex-encoded digests
- One-shot and streaming hash APIs

#### Key pairs
- Generation of **DSA**, **RSA**, **ECC**, **ECDH**, **ECDSA**, **ED25519** and **X25519** key pairs
- Public key stored as non-secret string; private key stored in secure `Password` (reference-counted, wipe-on-destroy)
- Load and save in **PEM** and **DER** formats
- Encrypted private-key storage (PKCS#8 / PBES2 with AES-CBC)
- Factory helpers (`Create`, `Load`) with automatic format and algorithm detection
- Public-only, private-only and combined key files

#### Key agreement (shared secrets)
- **ECDH** shared-secret derivation (secp256r1, secp384r1, secp521r1)
- **X25519** shared-secret derivation
- Result returned as a secure `Password`

#### Digital signatures
- **DSA** signer / verifier
- **ECDSA** (ECP + SHA-256) signer / verifier
- **ED25519** signer / verifier
- **RSA** (PKCS#1 v1.5 + SHA-256) signer / verifier
- One-shot and streaming sign/verify APIs

#### Secure storage
- **Password** – reference-counted container for secrets and binary key material with automatic wipe when the last owner is destroyed
- **Vault** – named password store (non-copyable, movable only)

#### Infrastructure
- Full integration with **StormByte-Buffer** for streaming pipelines
- Crypto++ backend for cryptographic primitives
- Optional Bzip2 backend for compression
- Complete Doxygen documentation on the public API
- LGPL-3.0 copyright headers on all public headers
- Visibility macros for shared-library builds

### Notes

- This is the first stable release of the StormByte-Crypto library.
- Requires a C++23 compliant compiler, CMake ≥ 3.12, StormByte-Buffer 1.0.0 and Crypto++.
- Designed as a building block for higher-level StormByte modules that need cryptography.

[Unreleased]: https://github.com/StormBytePP/StormByte-Crypto/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/StormBytePP/StormByte-Crypto/releases/tag/1.0.0