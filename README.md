# StormByte-Crypto

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![C++26](https://img.shields.io/badge/C%2B%2B-26-00599C?logo=c%2B%2B&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.28+-064F8C?logo=cmake&logoColor=white)
![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)
[![CI](https://github.com/StormBytePP/StormByte-Crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/StormBytePP/StormByte-Crypto/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor-StormBytePP-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/StormBytePP)

This repository is **StormByte Crypto**: hash, compress, encrypt, sign and key agreement for the StormByte C++ suite.

It depends on [StormByte Base](https://github.com/StormBytePP/StormByte) and [StormByte Buffer](https://github.com/StormBytePP/StormByte-Buffer). Public headers live under `StormByte/crypto/`. Crypto++ stays in the private tree: installed headers never mention `CryptoPP::`. With a static Crypto++ link, consumers do not install it.

The suite is split on purpose. Base, Buffer, Config, Database, Logger, Multimedia, Network and System are **other repositories**. This one does not implement them.

## What this module does

- **Hasher** — SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s. One-shot hex digest or a `Buffer::Consumer` that yields the digest when the source closes.
- **Compressor** — Zlib, Gzip, BZip2. Same block / stream contract as the rest of the module.
- **Symmetric crypter** — AES CBC, AES-GCM, ChaCha20-Poly1305, Camellia, Serpent, Twofish. Keys from `Password` via PBKDF2-HMAC-SHA256 (600 000 iterations). Authenticated modes fail closed on a bad tag or a wrong password.
- **Asymmetric crypter** — RSA OAEP-SHA and ECC ECIES. `Strategy::Native` is one PK transform per blob. `Strategy::Hybrid` wraps a random AES-256-GCM session key. Decrypt auto-detects the envelope.
- **Signer** — DSA, RSA PKCS#1 v1.5 + SHA-256, ECDSA, Ed25519. Block and streaming sign / verify.
- **Secret** — ECDH on secp256r1 / secp384r1 / secp521r1, and X25519. The shared secret is a `Password`, not a `std::string`.
- **KeyPair** — Generate, persist PEM or DER, optional PKCS#8 (PBES2 + PBKDF2 + AES-256-CBC, OpenSSL-compatible). Public key travels as Base64 SPKI; private key stays in a `Password`.
- **Password / Vault** — reference-counted wiped buffer; named store. Last owner zeros the bytes. Vault is movable, not copyable.
- **Buffer-first I/O** — `std::span<const std::byte>` → `Buffer::WriteOnly` for blocks; `Buffer::Consumer` in / out for pipelines (Network, Multimedia).

## The rest of the suite

| Module | Role |
| --- | --- |
| [Base](https://github.com/StormBytePP/StormByte) | Exceptions, `Expected`, little-endian serialization, strings, concepts — the suite root |
| [Buffer](https://github.com/StormBytePP/StormByte-Buffer) | FIFO, SharedFIFO, Ring, Producer/Consumer and multi-stage pipelines |
| [Config](https://github.com/StormBytePP/StormByte-Config) | Human-readable text and versioned binary documents (groups, lists, raw bytes) |
| [Crypto](https://github.com/StormBytePP/StormByte-Crypto) | This repository |
| [Database](https://github.com/StormBytePP/StormByte-Database) | One API for SQLite, PostgreSQL and MariaDB: prepared statements and RAII transactions |
| [Logger](https://github.com/StormBytePP/StormByte-Logger) | Stream logger with levels, headers, human-readable sizes and redaction (`ThreadedLog`) |
| [Multimedia](https://github.com/StormBytePP/StormByte-Multimedia) | Decode, encode and containers without raw FFmpeg types; codecs enabled only if present |
| [Network](https://github.com/StormBytePP/StormByte-Network) | Framed packets, Client/Server, IPv4/IPv6 TCP and Buffer pipelines (compress/encrypt) |
| [System](https://github.com/StormBytePP/StormByte-System) | Processes, pipes and environment variables across Linux, Windows and macOS |

Docs sites (when published): [Base](https://dev.stormbyte.org/StormByte), [Buffer](https://dev.stormbyte.org/StormByte-Buffer), [Config](https://dev.stormbyte.org/StormByte-Config), [Crypto](https://dev.stormbyte.org/StormByte-Crypto), [Database](https://dev.stormbyte.org/StormByte-Database), [Logger](https://dev.stormbyte.org/StormByte-Logger), [Multimedia](https://dev.stormbyte.org/StormByte-Multimedia), [Network](https://dev.stormbyte.org/StormByte-Network), [System](https://dev.stormbyte.org/StormByte-System).

## Table of Contents

- [What this module does](#what-this-module-does)
- [The rest of the suite](#the-rest-of-the-suite)
- [Installation](#installation)
- [Usage](#usage)
  - [Factories](#factories)
  - [Password and Vault](#password-and-vault)
  - [Hash and compress](#hash-and-compress)
  - [Symmetric encrypt](#symmetric-encrypt)
  - [Asymmetric encrypt](#asymmetric-encrypt)
  - [KeyPair on disk](#keypair-on-disk)
  - [Sign and verify](#sign-and-verify)
  - [Key agreement](#key-agreement)
- [Contributing](#contributing)
- [License](#license)

## Installation

Needs a C++26 compiler, CMake 3.28 or newer, [StormByte Base](https://github.com/StormBytePP/StormByte) ≥ 1.0.0 and [StormByte Buffer](https://github.com/StormBytePP/StormByte-Buffer) ≥ 1.0.0. Crypto++ and libbzip2 are build dependencies. Prefer a **static** Crypto++ link when you redistribute.

```sh
git clone --recursive https://github.com/StormBytePP/StormByte-Crypto.git
cd StormByte-Crypto
cmake -S . -B build
cmake --build build
```

## Usage

Headers are `#include <StormByte/crypto/….hxx>`. Namespace root is `StormByte::Crypto`.

Nothing in the public tree includes Crypto++. Private headers are not installed.

### Factories

```cpp
auto hasher = Hasher::Create(Hasher::Type::SHA256);
auto zip    = Compressor::Create(Compressor::Type::Zlib, 6);
auto aes    = Crypter::Create(Crypter::Type::AES_GCM, password);
auto rsaKp  = KeyPair::RSA::Generate(2048);
auto rsa    = Crypter::Create(Crypter::Type::RSA, rsaKp);          // Hybrid by default
auto signer = Signer::Create(Signer::Type::ECDSA, ecdsaKp);
auto ecdh   = Secret::Create(Secret::Type::ECDH, ecdhKp);
```

Concrete types (`Crypter::AES_GCM`, `KeyPair::X25519`, `Signer::ED25519`, …) construct the same way without going through `Create`.

### Password and Vault

`Password` is the only public container for secret bytes (passphrases, private key DER, shared secrets). Copies share the buffer; the last owner wipes it.

```cpp
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/vault.hxx>
#include <StormByte/crypto/crypter/generic.hxx>

using namespace StormByte::Crypto;

Password db("s3cret-from-env");
Vault vault;
vault.Store("database", db);
vault.Store("api", Password("token-xyz"));

if (auto p = vault.Get("database")) {
	auto aes = Crypter::Create(Crypter::Type::AES_GCM, *p);
}

if (*vault.Get("database") == db)
	; // constant-time compare of the bytes

vault.Remove("api");
vault.Clear();
```

`Vault` is movable, not copyable. A move leaves the source empty.

### Hash and compress

```cpp
#include <StormByte/crypto/hasher/generic.hxx>
#include <StormByte/crypto/compressor/generic.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/buffer/producer.hxx>

using namespace StormByte::Crypto;

auto sha = Hasher::Create(Hasher::Type::SHA256);
auto zip = Compressor::Create(Compressor::Type::Zlib, 6);

StormByte::Buffer::FIFO digest, packed;
const char msg[] = "payload";
const auto span = std::span<const std::byte>(
	reinterpret_cast<const std::byte*>(msg), sizeof(msg) - 1);

sha->Hash(span, digest);       // hex digest
zip->Compress(span, packed);

StormByte::Buffer::Producer prod;
prod.Write(msg);
prod.Close();
auto hashed = sha->Hash(prod.Consumer());   // Consumer → hex
```

### Symmetric encrypt

Password → random salt + PBKDF2-HMAC-SHA256 → key. AES-GCM and ChaCha20-Poly1305 authenticate; a wrong password or a flipped bit returns `false`.

```cpp
#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/buffer/producer.hxx>

using namespace StormByte::Crypto;

Password password("SecurePassword123!");
Crypter::AES_GCM gcm(password);

StormByte::Buffer::FIFO encrypted, decrypted;
const char msg[] = "authenticated payload";
const auto span = std::span<const std::byte>(
	reinterpret_cast<const std::byte*>(msg), sizeof(msg) - 1);

gcm.Encrypt(span, encrypted);
gcm.Decrypt(
	std::span<const std::byte>(encrypted.Data().data(), encrypted.Data().size()),
	decrypted);

StormByte::Buffer::Producer prod;
prod.Write(msg);
prod.Close();
auto cipher = gcm.Encrypt(prod.Consumer());
auto plain  = gcm.Decrypt(cipher);
```

CBC siblings (AES, Camellia, Serpent, Twofish) use the same `Encrypt` / `Decrypt` names.

### Asymmetric encrypt

`Native` is one PK operation per blob (small messages). `Hybrid` is a random AES-256-GCM key wrapped with the recipient public key (anything that would be painful as raw RSA/ECIES). Decrypt reads the header and picks the path.

```cpp
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/buffer/fifo.hxx>

using namespace StormByte::Crypto;

auto kp = KeyPair::RSA::Generate(2048);
Crypter::RSA hybrid(kp);                                 // Strategy::Hybrid
Crypter::RSA native(kp, Crypter::Asymmetric::Strategy::Native);

StormByte::Buffer::FIFO out;
hybrid.Encrypt(span, out);
hybrid.Decrypt(
	std::span<const std::byte>(out.Data().data(), out.Data().size()),
	out);
```

ECC (`Crypter::ECC` + `KeyPair::ECC`) is the same API.

### KeyPair on disk

| Format | Meaning |
| --- | --- |
| `PEM` | OpenSSL text (`BEGIN` / Base64). Default. |
| `DER` | Raw ASN.1. Same family as many `.cer` / `.crt` blobs. |

```cpp
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/password.hxx>

using namespace StormByte::Crypto;

auto kp = KeyPair::RSA::Generate(2048);
kp->Save("/tmp/keys", "app", KeyPair::StorageFormat::PEM);

Password wrap("disk-secret");
kp->Save("/tmp/keys", "app-enc", KeyPair::StorageFormat::PEM, wrap);

auto loaded = KeyPair::Load("/tmp/keys/app.pub.pem", "/tmp/keys/app.pem");
auto enc    = KeyPair::Load("/tmp/keys/app-enc.pub.pem", "/tmp/keys/app-enc.pem", wrap);
```

Wrong or missing wrap password fails closed (`nullptr`). Type comes from the OID (RSA, DSA, EC, Ed25519, X25519). Generate → Save → Load stays usable for encrypt, sign and share. X25519 also understands raw 32-byte library form.

### Sign and verify

```cpp
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/signer/generic.hxx>
#include <StormByte/buffer/fifo.hxx>

using namespace StormByte::Crypto;

auto kp = KeyPair::ED25519::Generate();
auto signer = Signer::Create(Signer::Type::ED25519, kp);

StormByte::Buffer::FIFO sig;
signer->Sign(span, sig);
bool ok = signer->Verify(span, std::string(
	reinterpret_cast<const char*>(sig.Data().data()), sig.Data().size()));
```

Streaming: `signer->Sign(consumer)` / `signer->Verify(consumer, signature)`.

### Key agreement

```cpp
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/x25519.hxx>

using namespace StormByte::Crypto;

auto alice = KeyPair::X25519::Generate();
auto bob   = KeyPair::X25519::Generate();

auto secret = Secret::Create(Secret::Type::X25519, alice);
auto shared = secret->Share(bob->PublicKey());   // Expected<Password>
```

ECDH is the same with `KeyPair::ECDH::Generate(256|384|521)` and `Secret::Type::ECDH`.

## Contributing

Issues only on this repository. Fork and open a pull request against `master`.

## License

GNU Lesser General Public License version 3 or later. See [LICENSE](LICENSE) and <https://www.gnu.org/licenses/lgpl-3.0.html>.
