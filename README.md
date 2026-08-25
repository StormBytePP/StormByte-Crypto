# StormByte-Crypto

![Linux](https://img.shields.io/badge/Linux-Supported-1793D1?logo=linux&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-Supported-0078D6?logo=windows&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-Supported-0078D6?logo=apple&logoColor=white)
![C++26](https://img.shields.io/badge/C%2B%2B-26-00599C?logo=c%2B%2B&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.12+-064F8C?logo=cmake&logoColor=white)
![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)
[![CI](https://github.com/StormBytePP/StormByte-Crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/StormBytePP/StormByte-Buffer/actions/workflows/ci.yml)

StormByte-Crypto is the cryptography module of the [StormByte](https://dev.stormbyte.org/StormByte) ecosystem: a modern, cross-platform C++26 library for hashing, compression, symmetric and asymmetric encryption, digital signatures, and key agreement.

It is built on [Crypto++](https://www.cryptopp.com/), but **fully encapsulates it**. Public headers never expose Crypto++ types. When the library is built with Crypto++ linked **statically**, consumers do **not** need Crypto++ installed on their system — a deliberate design goal.

## Table of Contents

- [Repository](#repository)
- [Installation](#installation)
- [Why StormByte-Crypto](#why-stormbyte-crypto)
- [Features](#features)
- [Security model](#security-model)
- [Dependencies](#dependencies)
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
- [Crypto overview](#crypto-overview)
- [Password and Vault](#password-and-vault)
- [KeyPair disk I/O (PEM / DER / CER)](#keypair-disk-io-pem--der--cer)
- [Public API](#public-api)
- [Examples](#examples)
	- [Symmetric encryption](#symmetric-encryption)
	- [Asymmetric encryption (Native and Hybrid)](#asymmetric-encryption-native-and-hybrid)
	- [Key agreement (ECDH / X25519)](#key-agreement-ecdh--x25519)
	- [Signing](#signing)
	- [Hashing](#hashing)
	- [Compression](#compression)
	- [KeyPair Save and Load](#keypair-save-and-load)
- [Design notes](#design-notes)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Repository

Source and CI live on GitHub:

- [StormByte-Crypto](https://github.com/StormBytePP/StormByte-Crypto)

Related documentation and sibling modules are linked from the [Modules](#modules) list above.

## Installation

```bash
git clone https://github.com/StormBytePP/StormByte-Crypto.git
cd StormByte-Crypto
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --install build
```

Exact CMake options (static Crypto++, install prefix, tests) depend on your StormByte meta-build. Prefer a **static** Crypto++ link when redistributing so downstream projects only need StormByte-Crypto.

## Why StormByte-Crypto

| Goal | How it is achieved |
|------|--------------------|
| **No Crypto++ in the public API** | Only StormByte types (`Password`, `KeyPair`, `Buffer`, factories). No `CryptoPP::` in installed headers. |
| **Static-friendly** | Crypto++ can be compiled into the library; end users need not install it. |
| **Secure secret handling** | `Password` and `Vault` with automatic wipe and shared ownership. |
| **Practical asymmetric crypto** | Pure PK encryption **and** hybrid envelopes (PK + AES-GCM), with auto-detect on decrypt. |
| **OpenSSL-friendly keys** | Load/Save PEM and DER (CER-style ASN.1 binary) with optional PKCS#8 encryption. |
| **Streaming as a first-class citizen** | `Buffer::Consumer` / `Producer` pipelines for large data. |
| **Consistent factories** | `Create(Type, …)` and concrete `Generate` / constructors across the module. |

## Features

### Symmetric encryption
- AES (CBC), AES-GCM (authenticated)
- ChaCha20-Poly1305 (authenticated)
- Camellia, Serpent, Twofish (CBC)
- Password-based keys via **PBKDF2-HMAC-SHA256** (600 000 iterations; OWASP guidance for SHA-256)

### Asymmetric encryption
- RSA (OAEP-SHA), ECC (ECIES)
- **Strategy**: `Native` (pure asymmetric) or `Hybrid` (random AES-GCM key wrapped with the public key)
- **Decrypt auto-detects** Hybrid vs Native

### Key agreement
- ECDH (secp256r1 / secp384r1 / secp521r1)
- X25519
- Shared secret returned as `Password` (not a long-lived plain `std::string`)

### Digital signatures
- DSA, RSA (PKCS#1 v1.5 + SHA-256), ECDSA, Ed25519
- Block and streaming sign/verify

### Hashing
- SHA-256, SHA-512, SHA3-256, SHA3-512
- BLAKE2b, BLAKE2s
- Block and streaming

### Compression
- Zlib / Gzip (Crypto++ filters)
- BZip2 (libbzip2)
- Block and streaming

### KeyPair persistence
- **PEM** (text, OpenSSL-compatible) and **DER** (binary ASN.1; same encoding family as many `.cer` / `.crt` key blobs)
- Separate public/private files or single-file load (public only, private only with public derivation, or concatenated PEM)
- Optional **PKCS#8** encryption of private keys (PBES2 + PBKDF2 + AES-256-CBC), interoperable with OpenSSL `pkcs8 -topk8 -v2 aes-256-cbc`
- Type detection from OIDs (RSA, DSA, EC, Ed25519, X25519)

### Secure containers
- **`Password`**: reference-counted secret; wipe when the last owner is destroyed
- **`Vault`**: named map of passwords; non-copyable, movable; `Clear` / `Remove` wipe entries

## Security model

1. **Secrets live in `Password`**
- Stored in a securely allocated buffer (implementation detail; not exposed as Crypto++ in public headers).
- Custom deleter zeroizes memory on last release.
- Copies share ownership; they do not duplicate secret bytes.

2. **`Vault` owns named passwords**
- Non-copyable to avoid accidental duplication of the whole store.
- Destructor and `Clear()` wipe all entries.

3. **Private keys are binary `Password`s**
- Public keys stay transport-friendly (e.g. Base64 of SPKI DER).
- Library structures avoid long-lived `std::string` private material.

4. **Symmetric derivation**
- Random salt + PBKDF2-HMAC-SHA256 with a high iteration count.

5. **Authenticated modes**
- AES-GCM and ChaCha20-Poly1305 fail closed on tag mismatch or wrong password.

6. **Hybrid envelopes**
- Large payloads use AES-GCM; only a random symmetric key is wrapped with the recipient public key.

7. **Encrypted private keys on disk**
- Optional password-protected PKCS#8; wrong or missing password fails closed (`nullptr` / `false`).

8. **Encapsulation**
- Private implementation headers are not installed.
- Application code that only uses StormByte-Crypto should never need `#include <cryptopp/...>`.

No API can stop a caller from copying secret bytes into an unmanaged buffer if they insist. The design makes the **secure path** the natural one and wipes library-owned copies aggressively.

## Dependencies

| Dependency | Role | Required when linking the consumer? |
|------------|------|--------------------------------------|
| **Crypto++** | Cryptographic primitives | **No**, if StormByte-Crypto was built with Crypto++ **static** |
| **libbzip2** | BZip2 | As configured in the build |
| **StormByte** (base) | Core utilities, Expected, exceptions | Yes |
| **StormByte-Buffer** | `Consumer` / `Producer` / FIFO | Yes |
| **OpenSSL CLI** | Optional; only for generating interop test fixtures | No (runtime library) |

## Modules

StormByte is split into focused libraries. This repository is **Crypto**. Sibling modules:

- [Base](https://dev.stormbyte.org/StormByte)
- [Buffer](https://dev.stormbyte.org/StormByte-Buffer)
- [Config](https://dev.stormbyte.org/StormByte-Config)
- **Crypto** (this repository)
- [Database](https://dev.stormbyte.org/StormByte-Database)
- [Logger](https://github.com/StormBytePP/StormByte-Logger.git)
- [Multimedia](https://dev.stormbyte.org/StormByte-Multimedia)
- [Network](https://dev.stormbyte.org/StormByte-Network)
- [System](https://dev.stormbyte.org/StormByte-System)

## Crypto overview

Namespaces under `StormByte::Crypto`:

| Namespace | Role |
|-----------|------|
| `Compressor` | Zlib, BZip2, … |
| `Crypter` | Symmetric and asymmetric encrypt/decrypt |
| `Hasher` | SHA-2/3, BLAKE2 |
| `KeyPair` | Key generation, material, **Save / Load** |
| `Signer` | Sign / verify |
| `Secret` | ECDH / X25519 shared secrets |
| *(root)* | `Password`, `Vault` |

### Buffer-centric I/O

- **Block**: `std::span<const std::byte>` or `Buffer::ReadOnly` → `Buffer::WriteOnly`, returns `bool`.
- **Streaming**: `Buffer::Consumer` in → `Buffer::Consumer` out (background worker + `Producer`).

This matches the rest of the StormByte stack and avoids bulk “encrypt this `std::string`” APIs.

## Password and Vault

`Password` is the library’s secure container for secret bytes (passwords, private key blobs, shared secrets).

```cpp
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/vault.hxx>

using namespace StormByte::Crypto;

Password dbPass("s3cret-from-env");
Vault vault;
vault.Store("database", dbPass);
vault.Store("api", Password("token-xyz"));

if (auto p = vault.Get("database")) {
	auto aes = Crypter::Create(Crypter::Type::AES_GCM, *p);
}

vault.Remove("api");
vault.Clear();
```

Equality is supported without exposing a raw C-string API for everyday use:

```cpp
if (*secretA == *secretB) {
	// same content
}
```

`Vault` is non-copyable and only movable. Moving transfers ownership of the stored `Password` instances; the source vault is left empty.

## KeyPair disk I/O (PEM / DER / CER)

`KeyPair::StorageFormat` selects on-disk encoding:

| Format | Description |
|--------|-------------|
| **`PEM`** | OpenSSL-style text (`-----BEGIN …-----`, Base64 body). Default for human-readable exchange. |
| **`DER`** | Raw ASN.1 binary. Same family of encoding used by many **`.cer` / `.crt`** key and certificate blobs (CER is typically DER under another extension). |

### Save

- **Pair**: public + private under a directory with a base name (`name.pub.pem` / `name.pem`, or `.pub.der` / `.der`).
- **Public only** / **private only**: dedicated overloads.
- **Encrypted private**: optional `Password`; writes PKCS#8 **EncryptedPrivateKeyInfo** (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC), readable by OpenSSL.

### Load

- Separate public and private paths (either may be empty when not needed).
- Single path: public only, private only (public derived when possible), or multi-block PEM.
- Encrypted private material requires a `Password`; wrong or missing password fails closed.
- Algorithm type is detected from ASN.1 OIDs (RSA, DSA, EC family, Ed25519, X25519).
- Intended interoperability with keys produced by **OpenSSL** (`genpkey`, `pkey`, `pkcs8`, PEM and DER).

Generated keys (RSA, DSA, ECC, ECDSA, ECDH, Ed25519) store standard serializable key material so a **Generate → Save → Load** round-trip remains usable for encrypt, sign, and share operations. X25519 may use compact raw 32-byte library form as well as OpenSSL PKCS#8.

## Public API

Typical factories:

```cpp
auto hasher = StormByte::Crypto::Hasher::Create(StormByte::Crypto::Hasher::Type::SHA256);
auto zlib   = StormByte::Crypto::Compressor::Create(StormByte::Crypto::Compressor::Type::Zlib, 5);
auto aes    = StormByte::Crypto::Crypter::Create(StormByte::Crypto::Crypter::Type::AES, password);
auto kp     = StormByte::Crypto::KeyPair::RSA::Generate(2048);
auto rsa    = StormByte::Crypto::Crypter::Create(StormByte::Crypto::Crypter::Type::RSA, kp);
auto signer = StormByte::Crypto::Signer::Create(StormByte::Crypto::Signer::Type::ECDSA, kp);
auto ecdh   = StormByte::Crypto::Secret::Create(StormByte::Crypto::Secret::Type::ECDH, ecdhKp);
```

Concrete types (`Crypter::AES_GCM`, `KeyPair::X25519`, `Signer::ED25519`, …) are available for direct construction as well. Authoritative signatures live under `lib/public/StormByte/crypto`.

## Examples

### Symmetric encryption

```cpp
#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/password.hxx>

Password password("SecurePassword123!");
Crypter::AES_GCM gcm(password);

StormByte::Buffer::FIFO encrypted, decrypted;
const std::string msg = "authenticated payload";

bool ok = gcm.Encrypt(
	std::span<const std::byte>(reinterpret_cast<const std::byte*>(msg.data()), msg.size()),
	encrypted
);
ok = gcm.Decrypt(
	std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
	decrypted
);
// Wrong password or corrupted ciphertext → Decrypt returns false
```

Streaming:

```cpp
StormByte::Buffer::Producer prod;
prod.Write(msg);
prod.Close();
auto cipherConsumer = gcm.Encrypt(prod.Consumer());
auto plainConsumer  = gcm.Decrypt(cipherConsumer);
```

### Asymmetric encryption (Native and Hybrid)

```cpp
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>

auto kp = KeyPair::RSA::Generate(2048);
Crypter::RSA rsa(kp);

StormByte::Buffer::FIFO out;

// Hybrid — recommended for larger messages
rsa.Encrypt(span, out, Crypter::Asymmetric::Strategy::Hybrid);

// Native — pure RSA / ECIES
rsa.Encrypt(span, out, Crypter::Asymmetric::Strategy::Native);

// Decrypt: no strategy argument; Hybrid is tried first, then Native
rsa.Decrypt(cipherSpan, plainOut);
```

### Key agreement (ECDH / X25519)

```cpp
#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/x25519.hxx>

auto a = KeyPair::ECDH::Generate(256);
auto b = KeyPair::ECDH::Generate(256);

Secret::ECDH sa(a);
Secret::ECDH sb(b);

auto secretA = sa.Share(b->PublicKey());
auto secretB = sb.Share(a->PublicKey());
// std::optional<Password>
if (secretA && secretB && *secretA == *secretB) {
	// use *secretA as keying material
}

auto x1 = KeyPair::X25519::Generate();
auto x2 = KeyPair::X25519::Generate();
Secret::X25519 sx1(x1);
auto shared = sx1.Share(x2->PublicKey());
```

Including `secret/ecdh.hxx` also provides `KeyPair::ECDH` (and likewise for X25519), so generation and agreement stay coherent with a single include.

### Signing

```cpp
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>

auto kp = KeyPair::ED25519::Generate();
Signer::ED25519 signer(kp);

StormByte::Buffer::FIFO sig;
signer.Sign(messageSpan, sig);
bool ok = signer.Verify(messageSpan, /* signature bytes from sig */);
```

### Hashing

```cpp
#include <StormByte/crypto/hasher/sha256.hxx>

Hasher::SHA256 h;
StormByte::Buffer::FIFO digest;
h.Hash(messageSpan, digest);
```

### Compression

```cpp
#include <StormByte/crypto/compressor/zlib.hxx>

Compressor::Zlib zlib;
StormByte::Buffer::FIFO compressed, plain;
zlib.Compress(messageSpan, compressed);
zlib.Decompress(compressed, plain);
```

### KeyPair Save and Load

```cpp
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>

using namespace StormByte::Crypto;

auto kp = KeyPair::RSA::Generate(2048);

// Plain PEM pair into a directory
kp->Save("/secure/keys", "service", KeyPair::StorageFormat::PEM);

// DER (binary ASN.1; CER-compatible encoding)
kp->Save("/secure/keys", "service_der", KeyPair::StorageFormat::DER);

// Encrypted private key (OpenSSL-compatible PKCS#8)
Password diskPass("file-encryption-passphrase");
kp->Save("/secure/keys", "service_enc", diskPass, KeyPair::StorageFormat::PEM);

// Load pair (plain)
auto loaded = KeyPair::Load(
	"/secure/keys/service.pub.pem",
	"/secure/keys/service.pem"
);

// Load encrypted private
auto loadedEnc = KeyPair::Load(
	"/secure/keys/service_enc.pub.pem",
	"/secure/keys/service_enc.pem",
	diskPass
);

// Single file (private only → public derived when possible)
auto fromPriv = KeyPair::Load("/secure/keys/service.pem");

// OpenSSL-generated PEM/DER paths work the same way when the encoding matches
```

## Design notes

### Encapsulation of Crypto++

- **Public** tree: stable StormByte types only.
- **Private** tree (`lib/private/...`): Crypto++ includes, template implementations, wipe helpers.
- Downstream code that only consumes this package should never need Crypto++ headers or a separate Crypto++ install when the library is built statically.

### Hybrid envelopes (conceptual layout)

1. Encrypt a random AES key under the recipient public key → `esk`
2. Length prefix for `esk`
3. Random IV for AES-GCM
4. AES-GCM ciphertext and tag for the payload

Decrypt tries this layout first; on failure it falls back to pure asymmetric decrypt. A corrupted envelope fails closed.

### Streaming

Streaming encrypt/decrypt/sign/hash/compress runs on a detached thread writing into a `Producer`. The caller holds the paired `Consumer` and should honour `EoF` and error flags (see `test/`).

### Intentionally deferred / rejected

- Exposing Crypto++ types in public headers (rejected by design).

## Testing

The `test/` tree covers compressors, symmetric and asymmetric crypters (including Hybrid and auto-detect), hashers, signers, ECDH/X25519, `Vault` / `Password`, and **KeyPair disk I/O**:

- OpenSSL-generated PEM/DER/encrypted fixtures (Unix shell and Windows batch generators)
- Library **Generate → Save → Load** round-trips (PEM/DER, cross-format, encrypted)
- Invalid / garbage inputs (empty, truncated, mismatched algorithms, missing password)

Fixtures use separate directories under the build tree so parallel `ctest -j` does not race. Enable tests in CMake and run CTest from the build directory.

## Contributing

Contributions are welcome. Please follow `CONTRIBUTING.md`, keep public headers free of Crypto++ types, and extend tests for security-sensitive changes (wipe paths, hybrid envelopes, key agreement, Save/Load and encrypted PKCS#8).

## License

This project is licensed under the **LGPL v3**. See the `LICENSE` file for details.

Crypto++ and other third-party components retain their own licenses. When linking statically, ensure your distribution complies with all applicable terms.
