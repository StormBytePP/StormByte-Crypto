#include <StormByte/crypto/implementation/encryption/aes_gcm.hxx>

#include <algorithm>
#include <aes.h>
#include <cryptlib.h>
#include <gcm.h>
#include <hex.h>
#include <filters.h>
#include <format>
#include <osrng.h>
#include <secblock.h>
#include <thread>
#include <pwdbased.h>
#include <span>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
ExpectedCryptoBuffer EncryptHelper(std::span<const std::byte> dataSpan, const std::string& password) noexcept {
try {
// GCM uses a 12-byte IV (96 bits) for optimal performance
constexpr size_t saltSize = 16;
constexpr size_t ivSize = 12;

CryptoPP::SecByteBlock salt(saltSize);
CryptoPP::SecByteBlock iv(ivSize);
CryptoPP::AutoSeededRandomPool rng;
rng.GenerateBlock(salt, salt.size());
rng.GenerateBlock(iv, iv.size());

// Derive key from password
CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
password.size(), salt, salt.size(), 10000);

// Encrypt using GCM mode
std::vector<uint8_t> encryptedData;
CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
encryption.SetKeyWithIV(key, key.size(), iv, iv.size());

CryptoPP::AuthenticatedEncryptionFilter ef(encryption,
new CryptoPP::VectorSink(encryptedData)
);

ef.Put(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes());
ef.MessageEnd();

// Prepend salt and IV
encryptedData.insert(encryptedData.begin(), salt.begin(), salt.end());
encryptedData.insert(encryptedData.begin() + salt.size(), iv.begin(), iv.end());

std::vector<std::byte> convertedData(encryptedData.size());
std::transform(encryptedData.begin(), encryptedData.end(), convertedData.begin(),
[](uint8_t byte) { return static_cast<std::byte>(byte); });

StormByte::Buffer::FIFO buffer;
(void)buffer.Write(convertedData);
return buffer;
} catch (const std::exception& e) {
return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
}
}

ExpectedCryptoBuffer DecryptHelper(std::span<const std::byte> encryptedSpan, const std::string& password) noexcept {
try {
constexpr size_t saltSize = 16;
constexpr size_t ivSize = 12;

if (encryptedSpan.size_bytes() < saltSize + ivSize) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Encrypted data too short to contain salt and IV");
}

CryptoPP::SecByteBlock salt(saltSize), iv(ivSize);
std::memcpy(salt.data(), encryptedSpan.data(), saltSize);
std::memcpy(iv.data(), encryptedSpan.data() + saltSize, ivSize);

encryptedSpan = encryptedSpan.subspan(saltSize + ivSize);

// Derive key from password
CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
password.size(), salt, salt.size(), 10000);

// Decrypt using GCM mode
std::vector<uint8_t> decryptedData;
CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
decryption.SetKeyWithIV(key, key.size(), iv, iv.size());

CryptoPP::AuthenticatedDecryptionFilter df(decryption,
new CryptoPP::VectorSink(decryptedData),
CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
);

df.Put(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes());
df.MessageEnd();

std::vector<std::byte> convertedData(decryptedData.size());
std::transform(decryptedData.begin(), decryptedData.end(), convertedData.begin(),
[](uint8_t byte) { return static_cast<std::byte>(byte); });

StormByte::Buffer::FIFO buffer;
(void)buffer.Write(convertedData);
return buffer;
} catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Authentication failed: {}", e.what());
} catch (const std::exception& e) {
return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
}
}
}

ExpectedCryptoBuffer AES_GCM::Encrypt(const std::string& data, const std::string& password) noexcept {
std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(data.data()), data.size());
return EncryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer AES_GCM::Encrypt(const Buffer::FIFO& data, const std::string& password) noexcept {
auto spanResult = const_cast<Buffer::FIFO&>(data).Extract(0);
if (!spanResult.has_value()) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to get span from input buffer");
}
std::span<const std::byte> dataSpan(spanResult.value().data(), spanResult.value().size());
return EncryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer AES_GCM::Encrypt(StormByte::Buffer::Consumer consumer, const std::string& password) noexcept {
SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

// Start async encryption
std::thread([consumer, producer, password]() mutable {
try {
// Extract all data from consumer (more efficient than manual loop)
auto allDataFifo = consumer.ExtractUntilEoF();
auto spanResult = allDataFifo.Extract(0);
if (!spanResult.has_value()) {
producer->Close();
return;
}

// Encrypt all at once (GCM requires all data for authentication)
std::span<const std::byte> dataSpan(spanResult.value().data(), spanResult.value().size());
auto encrypted = EncryptHelper(dataSpan, password);

if (!encrypted.has_value()) {
producer->Close();
return;
}

// Write result
auto extracted = encrypted.value().Extract(0);
if (!extracted.has_value()) {
producer->Close();
return;
}
(void)producer->Write(std::move(extracted.value()));
producer->Close();

} catch (...) {
producer->Close();
}
}).detach();

return producer->Consumer();
}

ExpectedCryptoBuffer AES_GCM::Decrypt(const std::string& encryptedData, const std::string& password) noexcept {
std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(encryptedData.data()), encryptedData.size());
return DecryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer AES_GCM::Decrypt(const Buffer::FIFO& encryptedData, const std::string& password) noexcept {
auto spanResult = const_cast<Buffer::FIFO&>(encryptedData).Extract(0);
if (!spanResult.has_value()) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to get span from input buffer");
}
std::span<const std::byte> dataSpan(spanResult.value().data(), spanResult.value().size());
return DecryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer AES_GCM::Decrypt(StormByte::Buffer::Consumer consumer, const std::string& password) noexcept {
SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

// Start async decryption
std::thread([consumer, producer, password]() mutable {
try {
// Extract all data from consumer (more efficient than manual loop)
auto allDataFifo = consumer.ExtractUntilEoF();
auto spanResult = allDataFifo.Extract(0);
if (!spanResult.has_value()) {
producer->Close();
return;
}

// Decrypt all at once (GCM requires all data for authentication)
std::span<const std::byte> dataSpan(spanResult.value().data(), spanResult.value().size());
auto decrypted = DecryptHelper(dataSpan, password);

if (!decrypted.has_value()) {
producer->Close();
return;
}

// Write result
auto extracted = decrypted.value().Extract(0);
if (!extracted.has_value()) {
producer->Close();
return;
}
(void)producer->Write(std::move(extracted.value()));
producer->Close();

} catch (...) {
producer->Close();
}
}).detach();

return producer->Consumer();
}

ExpectedCryptoString AES_GCM::RandomPassword(size_t size) noexcept {
try {
CryptoPP::AutoSeededRandomPool rng;
CryptoPP::SecByteBlock password(size);
rng.GenerateBlock(password, password.size());

std::string passwordStr;
CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(passwordStr));
encoder.Put(password, password.size());
encoder.MessageEnd();

return passwordStr;
} catch (const std::exception& e) {
return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
}
}
