#include <StormByte/crypto/implementation/encryption/dsa.hxx>

#include <cryptlib.h>
#include <base64.h>
#include <dsa.h>
#include <hex.h>
#include <osrng.h>
#include <filters.h>
#include <string>
#include <future>
#include <iostream>
#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
    std::string SerializeKey(const CryptoPP::DSA::PrivateKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    std::string SerializeKey(const CryptoPP::DSA::PublicKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    CryptoPP::DSA::PublicKey DeserializePublicKey(const std::string& keyString) {
        CryptoPP::DSA::PublicKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key
        return key;
    }

    CryptoPP::DSA::PrivateKey DeserializePrivateKey(const std::string& keyString) {
        CryptoPP::DSA::PrivateKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key
        return key;
    }
}

ExpectedKeyPair DSA::GenerateKeyPair(const int& keyStrength) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Generate the private key
        CryptoPP::DSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, keyStrength);

        // Generate the public key
        CryptoPP::DSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);

        // Validate the keys
        if (!privateKey.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }
        if (!publicKey.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Public key validation failed");
        }

        // Serialize the keys
        std::string serializedPrivateKey = SerializeKey(privateKey);
        std::string serializedPublicKey = SerializeKey(publicKey);

        // Return the key pair
        return KeyPair{
            .Private = serializedPrivateKey,
            .Public = serializedPublicKey,
        };
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>("Unexpected error during key generation: " + std::string(e.what()));
    }
}

ExpectedCryptoFutureString DSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the private key
        CryptoPP::DSA::PrivateKey key = DeserializePrivateKey(privateKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }

        // Initialize the signer
        CryptoPP::DSA::Signer signer(key);

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
        return StormByte::Unexpected<Exception>("DSA signing failed: " + std::string(e.what()));
    }
}

bool DSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoPP::DSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoPP::DSA::Verifier verifier(key);

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

StormByte::Buffers::Consumer DSA::Sign(const Buffers::Consumer consumer, const std::string& privateKey) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, privateKey]() {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Deserialize and validate the private key
            CryptoPP::DSA::PrivateKey key = DeserializePrivateKey(privateKey);
            if (!key.Validate(rng, 3)) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }

            // Initialize the signer
            CryptoPP::DSA::Signer signer(key);

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

bool DSA::Verify(const Buffers::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoPP::DSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoPP::DSA::Verifier verifier(key);

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