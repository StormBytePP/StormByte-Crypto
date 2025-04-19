#include <StormByte/crypto/implementation/encryption/ecc.hxx>

#include <base64.h>
#include <cryptlib.h>
#include <eccrypto.h>
#include <filters.h>
#include <format>
#include <osrng.h>
#include <oids.h>
#include <string>
#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
    using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;

    std::string SerializeKey(const ECIES::PrivateKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save the key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    std::string SerializeKey(const ECIES::PublicKey& key) {
        std::string keyString;
        CryptoPP::ByteQueue queue;
        key.Save(queue); // Save the key in ASN.1 format
        CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
        queue.CopyTo(encoder);
        encoder.MessageEnd();
        return keyString;
    }

    ECIES::PrivateKey DeserializePrivateKey(const std::string& keyString) {
        ECIES::PrivateKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key

        // Explicitly initialize curve parameters
        key.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256r1());

        return key;
    }

    ECIES::PublicKey DeserializePublicKey(const std::string& keyString) {
        ECIES::PublicKey key;
        CryptoPP::Base64Decoder decoder;
        CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
        key.Load(decoder); // Load the decoded key

        // Explicitly initialize curve parameters
        key.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp256r1());

        return key;
    }

    // Helper function to map curve names to CryptoPP::OID
    std::optional<CryptoPP::OID> GetCurveOID(const std::string& curve_name) {
        if (curve_name == "secp256r1") {
            return CryptoPP::ASN1::secp256r1();
        } else if (curve_name == "secp384r1") {
            return CryptoPP::ASN1::secp384r1();
        } else if (curve_name == "secp521r1") {
            return CryptoPP::ASN1::secp521r1();
        }
        return std::nullopt; // Unknown curve name
    }
}

ExpectedKeyPair ECC::GenerateKeyPair(const std::string& curve_name) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Map curve_name to CryptoPP::OID
        auto curve_oid = GetCurveOID(curve_name);
        if (!curve_oid.has_value()) {
            return StormByte::Unexpected<Exception>("Unknown curve name: " + curve_name);
        }

        // Generate private key
        ECIES::PrivateKey privateKey;
        privateKey.Initialize(rng, curve_oid.value());

        // Generate public key
        ECIES::PublicKey publicKey;
        privateKey.MakePublicKey(publicKey);

        // Serialize keys
        KeyPair keyPair{
            .Private = SerializeKey(privateKey),
            .Public = SerializeKey(publicKey),
        };

        return keyPair;
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>("Failed to generate ECC keys: " + std::string(e.what()));
    }
}

ExpectedCryptoFutureBuffer ECC::Encrypt(const std::string& message, const std::string& publicKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize, initialize, and validate the public key
        ECIES::PublicKey key = DeserializePublicKey(publicKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Public key validation failed");
        }

        // Initialize the encryptor
        ECIES::Encryptor encryptor(key);

        // Perform encryption
        std::string encryptedMessage;
        CryptoPP::StringSource ss(message, true,
                                    new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                                                                    new CryptoPP::StringSink(encryptedMessage)));

        // Convert the encrypted message into a buffer
        StormByte::Buffers::Simple buffer;
        buffer << encryptedMessage;

        std::promise<StormByte::Buffers::Simple> promise;
        promise.set_value(std::move(buffer));
        return promise.get_future();
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>(std::string("ECC encryption failed: ") + e.what());
    }
}    

ExpectedCryptoFutureString ECC::Decrypt(const StormByte::Buffers::Simple& encryptedBuffer, const std::string& privateKey) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;

        // Deserialize, initialize, and validate the private key
        ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
        if (!key.Validate(rng, 3)) {
            return StormByte::Unexpected<Exception>("Private key validation failed");
        }

        // Initialize the decryptor
        ECIES::Decryptor decryptor(key);

        // Perform decryption
        std::string decryptedMessage;
        std::string encryptedString(reinterpret_cast<const char*>(encryptedBuffer.Data().data()), encryptedBuffer.Size());
        CryptoPP::StringSource ss(encryptedString, true,
                                    new CryptoPP::PK_DecryptorFilter(rng, decryptor,
                                                                    new CryptoPP::StringSink(decryptedMessage)));

        return decryptedMessage;
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>(std::string("ECC decryption failed: ") + e.what());
    }
}

StormByte::Buffers::Consumer ECC::Encrypt(const Buffers::Consumer consumer, const std::string& publicKey) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, publicKey]() {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Deserialize, initialize, and validate the public key
            ECIES::PublicKey key = DeserializePublicKey(publicKey);
            if (!key.Validate(rng, 3)) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }

            // Initialize the encryptor
            ECIES::Encryptor encryptor(key);

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

StormByte::Buffers::Consumer ECC::Decrypt(const Buffers::Consumer consumer, const std::string& privateKey) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, privateKey]() {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Deserialize, initialize, and validate the private key
            ECIES::PrivateKey key = DeserializePrivateKey(privateKey);
            if (!key.Validate(rng, 3)) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }

            // Initialize the decryptor
            ECIES::Decryptor decryptor(key);

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