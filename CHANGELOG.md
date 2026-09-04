# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Summary]

StormByte Crypto is the cryptography module of the StormByte C++ suite.

It depends on StormByte Base and StormByte Buffer. This repository is not Base, Buffer, Config, Database, Logger, Multimedia, Network or System.

Public headers under `StormByte/crypto/` cover Hasher, Compressor, Crypter (symmetric and asymmetric), Signer, Secret, KeyPair, Password and Vault. Crypto++ never leaves the private tree.

If you landed here from a release link and have not read the tree:

- What this module is, how to build it, and short examples: [README.md](https://github.com/StormBytePP/StormByte-Crypto/blob/master/README.md)
- License: GNU Lesser General Public License version 3 or later, [LICENSE](https://github.com/StormBytePP/StormByte-Crypto/blob/master/LICENSE)

## [1.0.0] - 2026-09-04

Initial public release of StormByte Crypto.

### Added

- Hasher: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s (block and stream, hex digest)
- Compressor: Zlib, Gzip, BZip2 with configurable level (block and stream)
- Symmetric crypter: AES CBC, AES-GCM, ChaCha20-Poly1305, Camellia, Serpent, Twofish
- Password-based keys via PBKDF2-HMAC-SHA256 (600 000 iterations)
- Asymmetric crypter: RSA OAEP-SHA, ECC ECIES
- `Strategy::Native` and `Strategy::Hybrid` (AES-256-GCM session key wrapped with the public key); decrypt auto-detects
- Signer: DSA, RSA PKCS#1 v1.5 + SHA-256, ECDSA, Ed25519 (block and stream)
- Secret: ECDH (secp256r1 / secp384r1 / secp521r1) and X25519; result is a `Password`
- KeyPair generate: DSA, RSA, ECC, ECDH, ECDSA, Ed25519, X25519
- KeyPair Save / Load: PEM and DER; public Base64; private `Password`; optional PKCS#8 (PBES2 + AES-256-CBC)
- `Password` — shared wiped secret; last owner zeros the bytes
- `Vault` — named `Password` store; movable, not copyable
- Factories: `Create` on Hasher, Compressor, Crypter, Signer, Secret, KeyPair
- StormByte Buffer pipelines (`Consumer` / `Producer`) on every transform
- Exception hierarchy with component prefixes
- Project version read from the `VERSION` file
- CMake 3.28 floor

### Notes

- Installed headers do not include Crypto++. Static Crypto++ means consumers do not install it.
- Authenticated modes and wrapped private keys fail closed on a bad password or a bad tag.
- Needs a C++26 compiler, StormByte Base ≥ 1.0.0, StormByte Buffer ≥ 1.0.0, and Crypto++ at build time.

[1.0.0]: https://github.com/StormBytePP/StormByte-Crypto/releases/tag/1.0.0
