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

The examples below show concise, copy-pastable usage patterns for every algorithm family defined in
`lib/public/StormByte/crypto/algorithm.hxx`. They follow the same high-level patterns used by the
unit tests in `test/`:

- Convenience APIs: accept/return `std::string` or `StormByte::Buffer::FIFO` for whole-message flows.
- Streaming APIs: accept a `StormByte::Buffer::Consumer` and return a `StormByte::Buffer::Consumer` for output.
- KeyPair-based APIs: generate a `KeyPair` and use it with `Asymmetric`, `Signer` or `Secret` helpers.

Code snippets below are intentionally short; see `test/` for full, real-world examples.

### Compression

All compressors support convenience string/buffer APIs and streaming (Producer/Consumer) APIs.

- `Algorithm::Compress::Gzip` (Crypto++ Gzip)

```cpp
// compress a string
StormByte::Crypto::Compressor c(StormByte::Crypto::Algorithm::Compress::Gzip);
auto out = c.Compress(std::string("hello world"));

// streaming: push input into a Producer and read compressed data from returned Consumer
StormByte::Buffer::FIFO fifo;
auto inputProducer = fifo.Producer();
auto compressedConsumer = c.Compress(fifo.Consumer());
inputProducer.Put("hello"); inputProducer.MessageEnd();
auto compressed = ReadAllFromConsumer(compressedConsumer);
```

- `Algorithm::Compress::Zlib` (Crypto++ ZlibCompressor/ZlibDecompressor)

```cpp
StormByte::Crypto::Compressor z(StormByte::Crypto::Algorithm::Compress::Zlib);
auto compressed = z.Compress(std::string("some large payload"));

// streaming: identical pattern as Gzip
```

- `Algorithm::Compress::Bzip2` (system `bzlib` / `libbzip2`)

```cpp
StormByte::Crypto::Compressor b(StormByte::Crypto::Algorithm::Compress::Bzip2);
auto compressed = b.Compress(std::string("data"));

// streaming uses bzlib under the hood; consumer helpers in tests show correct usage
```

### Symmetric

Symmetric ciphers expose `Encrypt` / `Decrypt` convenience and streaming helpers. The constructor accepts
an `Algorithm::Symmetric` value and a password/key string (or derivation params according to your build).

- AES (CBC)

```cpp
StormByte::Crypto::Symmetric s(StormByte::Crypto::Algorithm::Symmetric::AES, "password-or-key");
auto enc = s.Encrypt("plaintext");
auto dec = s.Decrypt(*enc);
```

- AES-GCM (authenticated)

```cpp
StormByte::Crypto::Symmetric g(StormByte::Crypto::Algorithm::Symmetric::AES_GCM, "key32bytes...");
auto cipher = g.Encrypt("message");
// Verify/Decrypt will return std::nullopt on auth failure
auto plain = g.Decrypt(*cipher);
```

- Camellia, ChaCha20, Serpent, Twofish

```cpp
StormByte::Crypto::Symmetric cam(StormByte::Crypto::Algorithm::Symmetric::Camellia, "key");
auto ctext = cam.Encrypt("data");
auto ptext = cam.Decrypt(*ctext);

StormByte::Crypto::Symmetric chacha(StormByte::Crypto::Algorithm::Symmetric::ChaCha20, "key");
// same Encrypt/Decrypt pattern for Serpent and Twofish
```

Streaming encryption mirrors compressors: pass a `Buffer::Consumer` to `Encrypt` and read from the returned consumer.

### Asymmetric

Asymmetric usage revolves around `KeyPair` generation and using `Asymmetric` to Encrypt/Decrypt.

- `Algorithm::Asymmetric::RSA`

```cpp
auto kp = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::RSA, /*params*/{});
StormByte::Crypto::Asymmetric rsa(StormByte::Crypto::Algorithm::Asymmetric::RSA, kp);
auto c = rsa.Encrypt("hello");
auto p = rsa.Decrypt(*c);
```

- `Algorithm::Asymmetric::ECC` (EC-based encryption / key exchange patterns used with `Secret`)

```cpp
auto kp1 = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC, /*curve params*/{});
auto kp2 = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC, /*curve params*/{});
// For EC-based key agreement use `Secret` / ECDH APIs instead of Encrypt/Decrypt for symmetric key derivation
```

### Hash

Hasher is simple: construct with an `Algorithm::Hash` value and call `Hash`.

- Blake2b / Blake2s

```cpp
StormByte::Crypto::Hasher h1(StormByte::Crypto::Algorithm::Hash::Blake2b);
auto digest = h1.Hash("payload"); // hex string

StormByte::Crypto::Hasher h2(StormByte::Crypto::Algorithm::Hash::Blake2s);
```

- SHA256 / SHA512

```cpp
StormByte::Crypto::Hasher s256(StormByte::Crypto::Algorithm::Hash::SHA256);
auto d = s256.Hash("data");
```

- SHA3-256 / SHA3-512

```cpp
StormByte::Crypto::Hasher sha3(StormByte::Crypto::Algorithm::Hash::SHA3_256);
auto dd = sha3.Hash("abc");
```

### Sign

Signing helpers use `KeyPair` and `Signer` to create and verify signatures.

- DSA / ECDSA / RSA

```cpp
auto kp = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC);
StormByte::Crypto::Signer signer(StormByte::Crypto::Algorithm::Sign::ECDSA, kp);
auto sig = signer.Sign("message");
bool ok = signer.Verify("message", *sig);
```

- Ed25519

```cpp
auto kp = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC /*or helper for Ed25519*/);
StormByte::Crypto::Signer ed(StormByte::Crypto::Algorithm::Sign::Ed25519, kp);
auto sig = ed.Sign("msg");
ed.Verify("msg", *sig);
```

### Secret Share (Key agreement)

Use `StormByte::Crypto::Secret` to derive a shared secret from two `KeyPair`s. Examples mirror the unit tests.

- ECDH

```cpp
auto a = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC);
auto b = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC);
StormByte::Crypto::Secret sa(StormByte::Crypto::Algorithm::SecretShare::ECDH, a);
sa.SetPeerPublicKey(b.PublicKey());
auto sharedA = sa.Content();
// symmetric key derived by both sides should match
```

- X25519

```cpp
auto a = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC /*or X25519 helper*/);
auto b = StormByte::Crypto::KeyPair::Generate(StormByte::Crypto::Algorithm::Asymmetric::ECC /*or X25519 helper*/);
StormByte::Crypto::Secret sA(StormByte::Crypto::Algorithm::SecretShare::X25519, a);
sA.SetPeerPublicKey(b.PublicKey());
auto key = sA.Content();
```

For streaming examples, inspect `test/compressors/*_test.cxx`, `test/aes_test.cxx`, `test/ecdsa_test.cxx`, and friends — they demonstrate both convenience and streaming workflows used above.


## Public API (high-level)

This is a concise listing of the main public classes and their typical usage patterns. See the `test/` directory for detailed examples and expected behaviors.

- `StormByte::Crypto::Algorithm` enums
  The library exposes a small set of enums (see `lib/public/StormByte/crypto/algorithm.hxx`) used across the public API. Current values include:

  - `Algorithm::Asymmetric`:
    - `ECC` — elliptic-curve public-key algorithms
    - `RSA` — RSA public-key algorithm

  - `Algorithm::Symmetric`:
    - `None`
    - `AES` (CBC)
    - `AES_GCM` (authenticated AES-GCM)
    - `Camellia`
    - `ChaCha20`
    - `Serpent`
    - `Twofish`

  - `Algorithm::Compress`:
    - `None`
    - `Bzip2` (uses system `bzlib` / `libbzip2`)
    - `Gzip` (Crypto++ `Gzip` filter)
    - `Zlib` (Crypto++ `ZlibCompressor` / `ZlibDecompressor`)

  - `Algorithm::Hash`:
    - `Blake2b`, `Blake2s`
    - `SHA256`, `SHA512`
    - `SHA3_256`, `SHA3_512`

  - `Algorithm::Sign`:
    - `DSA`, `ECDSA`, `RSA`, `Ed25519`

  - `Algorithm::SecretShare`:
    - `ECDH`, `X25519`

  See the public header `lib/public/StormByte/crypto/algorithm.hxx` for the authoritative list.

- `StormByte::Crypto::Hasher`
  - Constructor: `Hasher(Algorithm::Hash algorithm)`
  - `std::optional<std::string> Hash(const std::string &data)` — returns hex encoded digest on success.

- `StormByte::Crypto::Compressor`
  - Constructor: `Compressor(Algorithm::Compress algorithm)`
  - `std::optional<std::string> Compress(const std::string &)`
  - `std::optional<StormByte::Buffer::FIFO> Compress(const StormByte::Buffer::FIFO &)`
  - `StormByte::Buffer::Consumer Compress(StormByte::Buffer::Consumer)` — streaming compressor that returns a consumer for compressed data.
  - `Decompress` variants mirror `Compress`.

- `StormByte::Crypto::Symmetric`
  - Constructor: `Symmetric(Algorithm::Symmetric, const std::string &password_or_key)`
  - `Encrypt/Decrypt` methods returning optional buffers; see tests for exact types.

- `StormByte::Crypto::Asymmetric` and `StormByte::Crypto::KeyPair`
  - `KeyPair::Generate(Algorithm::Asymmetric, params)` — generate a key pair for RSA/EC.
  - `Asymmetric` constructor accepts an algorithm and a `KeyPair` and provides `Encrypt/Decrypt`.

- `StormByte::Crypto::Signer`
  - Construct with algorithm+keypair or just a `KeyPair`; provides `Sign` and `Verify` methods.

- `StormByte::Crypto::Secret` (key agreement helpers)
  - Used for ECDH/X25519 workflows: set peer public key and call `Content()` to derive shared secret.

Test locations and usage notes
- The test suite is the most complete usage reference — see the `test/` folder at the repository root. Tests are grouped by functionality (compressors, hashers, encryptors, signers, etc.) and demonstrate both convenience and streaming APIs.
- Compression streaming: prefer `Compressor::Compress(Buffer::Consumer)` / `Decompress(Buffer::Consumer)` and read output with the consumer helpers (see `test/helpers.hxx`).
- Bzip2: because Crypto++ does not provide Bzip2 filters, the project uses the system `bzlib` API for Bzip2 streaming and the `Bzip2` implementation will require `libbzip2` on the target platform.

## Contributing

Contributions are welcome! Please follow the guidelines in the `CONTRIBUTING.md` file.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

