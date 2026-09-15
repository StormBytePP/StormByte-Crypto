# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Summary]

StormByte Crypto is the cryptography module of the StormByte C++ suite.

It depends on [StormByte Base](https://github.com/StormBytePP/StormByte) and [StormByte Buffer](https://github.com/StormBytePP/StormByte-Buffer). This repository is not Base, Buffer, Config, Database, Logger, Multimedia, Network or System.

Public headers under `StormByte/crypto/` cover Hasher, Compressor, Crypter (symmetric and asymmetric), Signer, Secret, KeyPair, Password and Vault. Crypto++ never leaves the private tree.

If you landed here from a release link and have not read the tree:

- What this module is, how to build it, and short examples: [README.md](https://github.com/StormBytePP/StormByte-Crypto/blob/master/README.md)
- License: GNU Lesser General Public License version 3 or later, [LICENSE](https://github.com/StormBytePP/StormByte-Crypto/blob/master/LICENSE)

## [Unreleased]

### Changed

- Doxygen (`ENABLE_DOC`) resolves Buffer, Logger and Base headers via `INCLUDE_PATH` and skips `thirdparty`. No dependency pin change.

## [1.1.0] - 2026-09-13

### Changed

- Exception hierarchy ported to `StormByte::Component`: `Crypto::Exception` names itself `"Crypto"`, and each per-component exception (`CompressorException`, `CrypterException`, `HasherException`, `KeyPairException`, `SecretException`, `SignerException`, `VaultException`) combines its own name with the parent's through its constructor instead of manual string concatenation. Removed the now-unneeded workaround for MSVC constructor-inheritance ambiguity.
- Bumped the StormByte Buffer dependency to 1.1.0.

### Added

- `VaultException`: `Vault::Get` on a missing entry now returns a dedicated exception instead of the generic `Exception`.
- Header-only `StormByte::Type::ByteInputRange` overloads for block hashing, compression, encryption, signing and signature verification. They accept byte-convertible input ranges such as `std::string_view`, `std::vector<uint8_t>` and `std::span`, then delegate to the existing byte-span APIs without changing their ABI.

### Fixed

- **Security hardening of `KeyPair` private-key handling**, found and closed during a full pre-release audit:
  - Private-key material (PKCS#8 DER, PBES2 plaintext/ciphertext) was never actually wiped from memory. The wipe helper constructed a *new* `CryptoPP::SecByteBlock` copy from the buffer's pointer and zeroed that copy instead of the original — `CryptoPP::SecBlock`'s `(pointer, length)` constructor always allocates and copies, it never wraps existing storage. Added a direct `SecureWipe` overload for `std::vector<unsigned char>` and wipe the original buffers (and `std::string` plaintext buffers) in place.
  - The shared `CryptoPP::AutoSeededRandomPool` used for salt/IV/key generation was a single process-wide instance accessed without synchronization. `AutoSeededRandomPool` is not safe for concurrent use, and the streaming encrypt/decrypt paths each spawn their own detached worker thread, so two concurrent streaming operations raced on the RNG's internal state. Made it `thread_local` instead — confirmed race-free with ThreadSanitizer (fully-instrumented `WITH_CRYPTOPP=BUNDLED` build; the `SYSTEM` build previously produced ABI-boundary false positives).
  - Private key files (`KeyPair::Save`/`SavePrivate`, encrypted or not, PEM or DER) were created with the OS-default file permissions, potentially group/world-readable depending on umask. They are now restricted to owner read/write (`0600`) right after writing. Public key files are unaffected. Best-effort on filesystems/platforms without POSIX permission bits.
  - `WriteFileBytes` (used by every `KeyPair::Save`/`SavePublic`/`SavePrivate` path) refuses to write through a pre-existing symlink at the destination path, closing a local TOCTOU attack where a symlink planted at the target filename would redirect the write to an arbitrary file.
- CMake: promote the system BZip2 imported target to global scope so `WITH_BZIP2=SYSTEM` resolves from the top-level directory.
- Tests: silence `-Werror=unused-variable` under GCC in the AES/Camellia/Serpent/Twofish symmetric crypter tests, where the decrypt result is intentionally unchecked (CBC either fails padding or succeeds with garbage).

### Notes

- Decompression of untrusted input is not size-bounded by this module (same as the underlying zlib/libbzip2); callers must bound it themselves. See [README.md](https://github.com/StormBytePP/StormByte-Crypto/blob/master/README.md#security-notes).
- Needs a C++26 compiler, [StormByte Base ≥ 1.1.0](https://github.com/StormBytePP/StormByte/releases/tag/1.1.0), [StormByte Buffer ≥ 1.1.0](https://github.com/StormBytePP/StormByte-Buffer/releases/tag/1.1.0), and Crypto++ at build time.

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
- Needs a C++26 compiler, [StormByte Base ≥ 1.1.0](https://github.com/StormBytePP/StormByte/releases/tag/1.1.0), [StormByte Buffer ≥ 1.1.0](https://github.com/StormBytePP/StormByte-Buffer/releases/tag/1.1.0), and Crypto++ at build time.

[Unreleased]: https://github.com/StormBytePP/StormByte-Crypto/compare/1.1.0...HEAD
[1.1.0]: https://github.com/StormBytePP/StormByte-Crypto/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/StormBytePP/StormByte-Crypto/releases/tag/1.0.0
