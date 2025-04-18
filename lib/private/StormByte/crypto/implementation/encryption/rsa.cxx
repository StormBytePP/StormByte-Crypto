#include <StormByte/crypto/implementation/encryption/rsa.hxx>

#include <cryptlib.h>
#include <base64.h>
#include <filters.h>
#include <format>
#include <osrng.h>
#include <rsa.h>
#include <secblock.h>
#include <string>
#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	std::string SerializeKey(const CryptoPP::RSA::PrivateKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	std::string SerializeKey(const CryptoPP::RSA::PublicKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	CryptoPP::RSA::PublicKey DeserializePublicKey(const std::string& keyString) {
		CryptoPP::RSA::PublicKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key
		return key;
	}

	CryptoPP::RSA::PrivateKey DeserializePrivateKey(const std::string& keyString) {
		CryptoPP::RSA::PrivateKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key
		return key;
	}
}

ExpectedKeyPair RSA::GenerateKeyPair(const int& keyStrength) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(rng, keyStrength);

		CryptoPP::RSA::PublicKey publicKey;
		publicKey.AssignFrom(privateKey);

		KeyPair keyPair{
			.Private = SerializeKey(privateKey),
			.Public = SerializeKey(publicKey),
		};

		return keyPair;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("Failed to generate RSA keys: {}", e.what());
	}
}

ExpectedCryptoFutureBuffer RSA::Encrypt(const std::string& message, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize, initialize, and validate the public key
        CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Public key validation failed");
        }

        // Initialize the encryptor
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

        // Perform encryption
        std::string encryptedMessage;
        CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(message.data()), message.size(), true,
                                  new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                                                                   new CryptoPP::StringSink(encryptedMessage)));

        // Convert the encrypted message into a buffer
        StormByte::Buffers::Simple buffer;
        buffer << encryptedMessage;

        std::promise<StormByte::Buffers::Simple> promise;
        promise.set_value(std::move(buffer));
        return promise.get_future();
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>(std::string("RSA encryption failed: ") + e.what());
    }
}

StormByte::Buffers::Consumer RSA::Encrypt(const Buffers::Consumer consumer, const std::string& publicKey) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, publicKey]() {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Deserialize, initialize, and validate the public key
            CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
            if (!key.Validate(rng, 3)) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }

            // Initialize the encryptor
            CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);

            constexpr size_t chunkSize = 4096;
            std::string encryptedChunk;

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
                encryptedChunk.clear();

                CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(inputData.data()), inputData.size(), true,
                                          new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                                                                           new CryptoPP::StringSink(encryptedChunk)));

                *producer << StormByte::Buffers::Simple(encryptedChunk.data(), encryptedChunk.size());
            }
        } catch (...) {
            *producer << StormByte::Buffers::Status::Error;
        }
    }).detach();

    return producer->Consumer();
}

ExpectedCryptoFutureString RSA::Decrypt(const StormByte::Buffers::Simple& encryptedBuffer, const std::string& privateKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize, initialize, and validate the private key
        CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }

        // Initialize the decryptor
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

        // Perform decryption
        std::string decryptedMessage;
        std::string encryptedString(reinterpret_cast<const char*>(encryptedBuffer.Data().data()), encryptedBuffer.Size());
        CryptoPP::StringSource ss(encryptedString, true,
                                  new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                                                                   new CryptoPP::StringSink(decryptedMessage)));

        return decryptedMessage;
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>(std::string("RSA decryption failed: ") + e.what());
    }
}

StormByte::Buffers::Consumer RSA::Decrypt(const Buffers::Consumer consumer, const std::string& privateKey) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, privateKey]() {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Deserialize, initialize, and validate the private key
            CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
            if (!key.Validate(rng, 3)) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }

            // Initialize the decryptor
            CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);

            constexpr size_t chunkSize = 4096;
            std::string decryptedChunk;

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

                const auto& encryptedData = readResult.value();
                decryptedChunk.clear();

                CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(encryptedData.data()), encryptedData.size(), true,
                                          new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                                                                           new CryptoPP::StringSink(decryptedChunk)));

                *producer << StormByte::Buffers::Simple(decryptedChunk.data(), decryptedChunk.size());
            }
        } catch (...) {
            *producer << StormByte::Buffers::Status::Error;
        }
    }).detach();

    return producer->Consumer();
}

// RSA Sign Implementation
ExpectedCryptoFutureString RSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the private key
        CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }

        // Initialize the signer
        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

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
        return StormByte::Unexpected<Exception>("RSA signing failed: " + std::string(e.what()));
    }
}

// RSA Verify Implementation
bool RSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(key);

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

// RSA Sign (Consumer/Producer Model)
StormByte::Buffers::Consumer RSA::Sign(const Buffers::Consumer consumer, const std::string& privateKey) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, privateKey]() {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Deserialize and validate the private key
            CryptoPP::RSA::PrivateKey key = DeserializePrivateKey(privateKey);
            if (!key.Validate(rng, 3)) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }

            // Initialize the signer
            CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Signer signer(key);

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

// RSA Verify (Consumer/Producer Model)
bool RSA::Verify(const Buffers::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize and validate the public key
        CryptoPP::RSA::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return false; // Public key validation failed
        }

        // Initialize the verifier
        CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA256>::Verifier verifier(key);

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