#include <StormByte/crypto/implementation/encryption/camellia.hxx>

#include <camellia.h>
#include <cryptlib.h>
#include <hex.h>
#include <modes.h>
#include <filters.h>
#include <format>
#include <future>
#include <osrng.h>
#include <secblock.h>
#include <thread>
#include <pwdbased.h>
#include <iostream>
#include <iomanip>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
    ExpectedCryptoFutureBuffer EncryptHelper(std::span<const std::byte> dataSpan, const std::string& password) noexcept {
        try {
            CryptoPP::SecByteBlock salt(16);
            CryptoPP::SecByteBlock iv(CryptoPP::Camellia::BLOCKSIZE);
            CryptoPP::AutoSeededRandomPool rng;
            rng.GenerateBlock(salt, salt.size());
            rng.GenerateBlock(iv, iv.size());

            CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
            pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
                             password.size(), salt, salt.size(), 10000);

            std::vector<uint8_t> encryptedData;
            CryptoPP::CBC_Mode<CryptoPP::Camellia>::Encryption encryption(key, key.size(), iv);
            CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes(), true,
                                      new CryptoPP::StreamTransformationFilter(encryption,
                                                                               new CryptoPP::VectorSink(encryptedData)));

            encryptedData.insert(encryptedData.begin(), salt.begin(), salt.end());
            encryptedData.insert(encryptedData.begin() + salt.size(), iv.begin(), iv.end());

            std::vector<std::byte> convertedData(encryptedData.size());
            std::transform(encryptedData.begin(), encryptedData.end(), convertedData.begin(),
                           [](uint8_t byte) { return static_cast<std::byte>(byte); });

            std::promise<StormByte::Buffers::Simple> promise;
            promise.set_value(StormByte::Buffers::Simple(std::move(convertedData)));
            return promise.get_future();
        } catch (const std::exception& e) {
            return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
        }
    }

    ExpectedCryptoFutureBuffer DecryptHelper(std::span<const std::byte> encryptedSpan, const std::string& password) noexcept {
        try {
            const size_t saltSize = 16;
            const size_t ivSize = CryptoPP::Camellia::BLOCKSIZE;

            if (encryptedSpan.size_bytes() < saltSize + ivSize) {
                return StormByte::Unexpected<StormByte::Crypto::Exception>("Encrypted data too short to contain salt and IV");
            }

            CryptoPP::SecByteBlock salt(saltSize), iv(ivSize);
            std::memcpy(salt.data(), encryptedSpan.data(), saltSize);
            std::memcpy(iv.data(), encryptedSpan.data() + saltSize, ivSize);

            encryptedSpan = encryptedSpan.subspan(saltSize + ivSize);

            CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
            pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
                             password.size(), salt, salt.size(), 10000);

            std::vector<uint8_t> decryptedData;
            CryptoPP::CBC_Mode<CryptoPP::Camellia>::Decryption decryption(key, key.size(), iv);
            CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes(), true,
                                      new CryptoPP::StreamTransformationFilter(decryption,
                                                                               new CryptoPP::VectorSink(decryptedData)));

            std::vector<std::byte> convertedData(decryptedData.size());
            std::transform(decryptedData.begin(), decryptedData.end(), convertedData.begin(),
                           [](uint8_t byte) { return static_cast<std::byte>(byte); });

            std::promise<StormByte::Buffers::Simple> promise;
            promise.set_value(StormByte::Buffers::Simple(std::move(convertedData)));
            return promise.get_future();
        } catch (const std::exception& e) {
            return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
        }
    }
}

// Encrypt Function Overloads
ExpectedCryptoFutureBuffer Camellia::Encrypt(const std::string& input, const std::string& password) noexcept {
    std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
    return EncryptHelper(dataSpan, password);
}

ExpectedCryptoFutureBuffer Camellia::Encrypt(const StormByte::Buffers::Simple& input, const std::string& password) noexcept {
    return EncryptHelper(input.Data(), password);
}

StormByte::Buffers::Consumer Camellia::Encrypt(const Buffers::Consumer consumer, const std::string& password) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, password]() {
        try {
            constexpr size_t chunkSize = 4096;
            CryptoPP::AutoSeededRandomPool rng;

            CryptoPP::SecByteBlock salt(16);
            CryptoPP::SecByteBlock iv(CryptoPP::Camellia::BLOCKSIZE);
            rng.GenerateBlock(salt, salt.size());
            rng.GenerateBlock(iv, iv.size());

            CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
            pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
                             password.size(), salt, salt.size(), 10000);

            *producer << StormByte::Buffers::Simple(reinterpret_cast<const char*>(salt.data()), salt.size());
            *producer << StormByte::Buffers::Simple(reinterpret_cast<const char*>(iv.data()), iv.size());

            CryptoPP::CBC_Mode<CryptoPP::Camellia>::Encryption encryption(key, key.size(), iv);
            std::vector<uint8_t> encryptedChunk;

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

                CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(inputData.data()), inputData.size(), true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::VectorSink(encryptedChunk)));

                *producer << StormByte::Buffers::Simple(reinterpret_cast<const char*>(encryptedChunk.data()), encryptedChunk.size());
            }
        } catch (...) {
            *producer << StormByte::Buffers::Status::Error;
        }
    }).detach();

    return producer->Consumer();
}

// Decrypt Function Overloads
ExpectedCryptoFutureBuffer Camellia::Decrypt(const std::string& input, const std::string& password) noexcept {
    std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
    return DecryptHelper(dataSpan, password);
}

ExpectedCryptoFutureBuffer Camellia::Decrypt(const StormByte::Buffers::Simple& input, const std::string& password) noexcept {
    return DecryptHelper(input.Data(), password);
}

StormByte::Buffers::Consumer Camellia::Decrypt(const Buffers::Consumer consumer, const std::string& password) noexcept {
    SharedProducerBuffer producer = std::make_shared<StormByte::Buffers::Producer>();

    std::thread([consumer, producer, password]() {
        try {
            constexpr size_t chunkSize = 4096;
            CryptoPP::SecByteBlock salt(16);
            CryptoPP::SecByteBlock iv(CryptoPP::Camellia::BLOCKSIZE);

            while (consumer.AvailableBytes() < salt.size()) {
                if (consumer.IsEoF()) {
                    *producer << StormByte::Buffers::Status::Error;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            auto saltResult = consumer.Read(salt.size());
            if (!saltResult.has_value()) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }
            std::memcpy(salt.data(), saltResult.value().data(), salt.size());

            while (consumer.AvailableBytes() < iv.size()) {
                if (consumer.IsEoF()) {
                    *producer << StormByte::Buffers::Status::Error;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            auto ivResult = consumer.Read(iv.size());
            if (!ivResult.has_value()) {
                *producer << StormByte::Buffers::Status::Error;
                return;
            }
            std::memcpy(iv.data(), ivResult.value().data(), iv.size());

            CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
            CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
            pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
                             password.size(), salt, salt.size(), 10000);

            CryptoPP::CBC_Mode<CryptoPP::Camellia>::Decryption decryption(key, key.size(), iv);
            std::vector<uint8_t> decryptedChunk;

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

                CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedData.data()), encryptedData.size(), true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::VectorSink(decryptedChunk)));

                *producer << StormByte::Buffers::Simple(reinterpret_cast<const char*>(decryptedChunk.data()), decryptedChunk.size());
            }
        } catch (...) {
            *producer << StormByte::Buffers::Status::Error;
        }
    }).detach();

    return producer->Consumer();
}

// RandomPassword Function
ExpectedCryptoFutureString Camellia::RandomPassword(const size_t& passwordSize) noexcept {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::SecByteBlock password(passwordSize);
        rng.GenerateBlock(password, passwordSize);

        std::string passwordString;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(passwordString));
        encoder.Put(password.data(), password.size());
        encoder.MessageEnd();

        return passwordString;
    } catch (const std::exception& e) {
        return StormByte::Unexpected<Exception>("Failed to generate random password: {}", e.what());
    }
}