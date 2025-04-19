#include <StormByte/crypto/implementation/encryption/ecdsa.hxx>

#include <cryptlib.h>
#include <base64.h>
#include <eccrypto.h>
#include <osrng.h>
#include <oids.h>
#include <filters.h>
#include <string>
#include <future>
#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
    using CryptoECDSA = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

    std::string SerializeKey(const CryptoECDSA::PrivateKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    std::string SerializeKey(const CryptoECDSA::PublicKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    CryptoECDSA::PublicKey DeserializePublicKey(const std::string& keyString) {
        CryptoECDSA::PublicKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource keySource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key
        return key;
    }

    CryptoECDSA::PrivateKey DeserializePrivateKey(const std::string& keyString) {
        CryptoECDSA::PrivateKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource keySource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key
        return key;
    }
}

// Key Pair Generation
ExpectedKeyPair ECDSA::GenerateKeyPair(const std::string& curveName) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Select the curve
        CryptoPP::OID curve;
        if (curveName == "secp256r1") {
            curve = CryptoPP::ASN1::secp256r1();
        } else if (curveName == "secp384r1") {
            curve = CryptoPP::ASN1::secp384r1();
        } else if (curveName == "secp521r1") {
            curve = CryptoPP::ASN1::secp521r1();
        } else {
            return StormByte::Unexpected<Exception>("Unknown curve name: " + curveName);
        }

        // Generate the private key
        CryptoECDSA::PrivateKey privateKey;
        privateKey.Initialize(rng, curve);

        // Generate the public key
        CryptoECDSA::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        // Validate the keys
        if (!privateKey.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }
        if (!publicKey.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Public key validation failed");
        }

        // Serialize the keys
        return KeyPair{
            .Private = SerializeKey(privateKey),
            .Public = SerializeKey(publicKey),
        };
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>("Unexpected error during key generation: " + std::string(e.what()));
    }
}

// Signing
ExpectedCryptoFutureString ECDSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the private key
        CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }

        // Initialize the signer
        CryptoECDSA::Signer signer(key);

        // Sign the message
        std::string signature;
        CryptoPP::StringSource ss(
            message, true,
            new CryptoPP::SignerFilter(
                rng, signer,
                new CryptoPP::StringSink(signature)
            )
        );

        return signature;
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>("ECDSA signing failed: " + std::string(e.what()));
    }
}

ExpectedCryptoFutureBuffer ECDSA::Sign(const Buffers::Simple& message, const std::string& privateKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the private key
        CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }

        // Initialize the signer
        CryptoECDSA::Signer signer(key);

        // Sign the message
        std::string signature;
        CryptoPP::StringSource ss(
            reinterpret_cast<const CryptoPP::byte*>(message.Data().data()), message.Size(), true,
            new CryptoPP::SignerFilter(rng, signer, new CryptoPP::StringSink(signature))
        );

        // Convert the signature to a buffer
        std::vector<std::byte> signatureBuffer(signature.size());
        std::transform(signature.begin(), signature.end(), signatureBuffer.begin(),
                       [](char c) { return static_cast<std::byte>(c); });

        std::promise<StormByte::Buffers::Simple> promise;
        promise.set_value(StormByte::Buffers::Simple(std::move(signatureBuffer)));
        return promise.get_future();
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>("ECDSA signing failed: " + std::string(e.what()));
    }
}

// Signing with Buffers::Consumer
StormByte::Buffers::Consumer ECDSA::Sign(const Buffers::Consumer consumer, const std::string& privateKey) noexcept {
    auto producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, privateKey]() {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Deserialize and validate the private key
            CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
            if (!key.Validate(rng, 3)) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }

            // Initialize the signer
            CryptoECDSA::Signer signer(key);

            constexpr size_t chunkSize = 4096;
            std::string signatureChunk;

            while (true) {
                size_t availableBytes = consumer.AvailableBytes();
                if (availableBytes == 0) {
                    if (consumer.IsEoF()) {
                        *producer << StormByte::Buffers::Status::EoF;
                        break;
                    } else {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                }

                size_t bytesToRead = std::min(availableBytes, chunkSize);
                auto readResult = consumer.Read(bytesToRead);
                if (!readResult.has_value()) {
                    *producer << StormByte::Buffers::Status::Error;
                    break;
                }

                const auto& inputData = readResult.value();
                signatureChunk.clear();

                // Sign the chunk
                CryptoPP::StringSource ss(
                    reinterpret_cast<const CryptoPP::byte*>(inputData.data()), inputData.size(), true,
                    new CryptoPP::SignerFilter(
                        rng, signer,
                        new CryptoPP::StringSink(signatureChunk)
                    )
                );

                *producer << StormByte::Buffers::Simple(signatureChunk.data(), signatureChunk.size());
            }
        } catch (...) {
            *producer << StormByte::Buffers::Status::Error;
        }
    }).detach();

    return producer->Consumer();
}

// Verification
bool ECDSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoECDSA::Verifier verifier(key);

        // Verify the signature
        bool result = false;
        CryptoPP::StringSource ss(
            signature + message, true,
            new CryptoPP::SignatureVerificationFilter(
                verifier,
                new CryptoPP::ArraySink((CryptoPP::byte*)&result, sizeof(result)),
                CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
            )
        );

        return result;
    } catch (const CryptoPP::Exception&) {
        return false; // Signature verification failed
    } catch (const std::exception&) {
        return false; // Other errors
    }
}

// Verification with Buffers::Simple
bool ECDSA::Verify(const Buffers::Simple& message, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoECDSA::Verifier verifier(key);

        // Verify the signature
        bool result = false;
        CryptoPP::StringSource ss(
            signature + std::string(reinterpret_cast<const char*>(message.Data().data()), message.Size()), true,
            new CryptoPP::SignatureVerificationFilter(
                verifier,
                new CryptoPP::ArraySink((CryptoPP::byte*)&result, sizeof(result)),
                CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
            )
        );

        return result;
    } catch (const CryptoPP::Exception&) {
        return false; // Signature verification failed
    } catch (const std::exception&) {
        return false; // Other errors
    }
}

// Verification with Buffers::Consumer
bool ECDSA::Verify(const Buffers::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoECDSA::Verifier verifier(key);

        constexpr size_t chunkSize = 4096;
        bool verificationResult = true;

        while (true) {
            size_t availableBytes = consumer.AvailableBytes();
            if (availableBytes == 0) {
                if (consumer.IsEoF()) {
                    break; // End of data
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
            }

            size_t bytesToRead = std::min(availableBytes, chunkSize);
            auto readResult = consumer.Read(bytesToRead);
            if (!readResult.has_value()) {
                return false; // Error reading data
            }

            const auto& inputData = readResult.value();

            // Verify the chunk
            CryptoPP::StringSource ss(
                signature + std::string(reinterpret_cast<const char*>(inputData.data()), inputData.size()), true,
                new CryptoPP::SignatureVerificationFilter(
                    verifier,
                    new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&verificationResult), sizeof(verificationResult)),
                    CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
                )
            );

            if (!verificationResult) {
                return false; // Verification failed
            }
        }

        return verificationResult; // Verification succeeded
    } catch (...) {
        return false; // Handle any unexpected errors
    }
}