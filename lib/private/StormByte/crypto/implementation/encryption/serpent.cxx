#include <StormByte/crypto/implementation/encryption/serpent.hxx>

#include <algorithm>
#include <serpent.h>
#include <cryptlib.h>
#include <hex.h>
#include <modes.h>
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
CryptoPP::SecByteBlock salt(16);
CryptoPP::SecByteBlock iv(CryptoPP::Serpent::BLOCKSIZE);
CryptoPP::AutoSeededRandomPool rng;
rng.GenerateBlock(salt, salt.size());
rng.GenerateBlock(iv, iv.size());

CryptoPP::SecByteBlock key(CryptoPP::Serpent::DEFAULT_KEYLENGTH);
CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
password.size(), salt, salt.size(), 10000);

std::vector<uint8_t> encryptedData;
CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption encryption(key, key.size(), iv);
CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes(), true,
new CryptoPP::StreamTransformationFilter(encryption,
new CryptoPP::VectorSink(encryptedData)));

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
const size_t saltSize = 16;
const size_t ivSize = CryptoPP::Serpent::BLOCKSIZE;

if (encryptedSpan.size_bytes() < saltSize + ivSize) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Encrypted data too short to contain salt and IV");
}

CryptoPP::SecByteBlock salt(saltSize), iv(ivSize);
std::memcpy(salt.data(), encryptedSpan.data(), saltSize);
std::memcpy(iv.data(), encryptedSpan.data() + saltSize, ivSize);

encryptedSpan = encryptedSpan.subspan(saltSize + ivSize);

CryptoPP::SecByteBlock key(CryptoPP::Serpent::DEFAULT_KEYLENGTH);
CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
password.size(), salt, salt.size(), 10000);

std::vector<uint8_t> decryptedData;
CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption decryption(key, key.size(), iv);
CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes(), true,
new CryptoPP::StreamTransformationFilter(decryption,
new CryptoPP::VectorSink(decryptedData)));

std::vector<std::byte> convertedData(decryptedData.size());
std::transform(decryptedData.begin(), decryptedData.end(), convertedData.begin(),
[](uint8_t byte) { return static_cast<std::byte>(byte); });

StormByte::Buffer::FIFO buffer;
(void)buffer.Write(convertedData);
return buffer;
} catch (const std::exception& e) {
return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
}
}
}

// Encrypt Function Overloads
ExpectedCryptoBuffer Serpent::Encrypt(const std::string& input, const std::string& password) noexcept {
std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
return EncryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer Serpent::Encrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept {
auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
if (!data.has_value()) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
}
std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
return EncryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer Serpent::Encrypt(Buffer::Consumer consumer, const std::string& password) noexcept {
SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

// Generate and write header synchronously
CryptoPP::AutoSeededRandomPool rng;
CryptoPP::SecByteBlock salt(16);
CryptoPP::SecByteBlock iv(CryptoPP::Serpent::BLOCKSIZE);
rng.GenerateBlock(salt, salt.size());
rng.GenerateBlock(iv, iv.size());

CryptoPP::SecByteBlock key(CryptoPP::Serpent::DEFAULT_KEYLENGTH);
CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
password.size(), salt, salt.size(), 10000);

std::vector<std::byte> headerBytes;
headerBytes.reserve(salt.size() + iv.size());
for (size_t i = 0; i < salt.size(); ++i) {
headerBytes.push_back(static_cast<std::byte>(salt[i]));
}
for (size_t i = 0; i < iv.size(); ++i) {
headerBytes.push_back(static_cast<std::byte>(iv[i]));
}
(void)producer->Write(std::move(headerBytes));

std::thread([consumer, producer, key = std::move(key), iv = std::move(iv)]() mutable {
try {
constexpr size_t chunkSize = 4096;
CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption encryption(key, key.size(), iv);
std::vector<uint8_t> encryptedChunk;
std::vector<std::byte> batchBuffer;
batchBuffer.reserve(chunkSize * 2);

while (!consumer.EoF()) {
size_t availableBytes = consumer.AvailableBytes();
if (availableBytes == 0) {
std::this_thread::sleep_for(std::chrono::milliseconds(10));
continue;
}

size_t bytesToRead = std::min(availableBytes, chunkSize);
auto spanResult = consumer.Span(bytesToRead);
if (!spanResult.has_value()) {
producer->Close();
return;
}

const auto& inputSpan = spanResult.value();
encryptedChunk.clear();

CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(inputSpan.data()), inputSpan.size(), true,
new CryptoPP::StreamTransformationFilter(encryption,
new CryptoPP::VectorSink(encryptedChunk)));

for (size_t i = 0; i < encryptedChunk.size(); ++i) {
batchBuffer.push_back(static_cast<std::byte>(encryptedChunk[i]));
}

if (batchBuffer.size() >= chunkSize) {
(void)producer->Write(std::move(batchBuffer));
batchBuffer.clear();
batchBuffer.reserve(chunkSize * 2);
consumer.Clean();
}
}
if (!batchBuffer.empty()) {
(void)producer->Write(std::move(batchBuffer));
}
producer->Close();
} catch (...) {
producer->Close();
}
}).detach();

return producer->Consumer();
}

// Decrypt Function Overloads
ExpectedCryptoBuffer Serpent::Decrypt(const std::string& input, const std::string& password) noexcept {
std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
return DecryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer Serpent::Decrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept {
auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
if (!data.has_value()) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
}
std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
return DecryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer Serpent::Decrypt(Buffer::Consumer consumer, const std::string& password) noexcept {
SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

std::thread([consumer, producer, password]() mutable {
try {
constexpr size_t chunkSize = 4096;
CryptoPP::SecByteBlock salt(16);
CryptoPP::SecByteBlock iv(CryptoPP::Serpent::BLOCKSIZE);

while (consumer.AvailableBytes() < salt.size()) {
if (!consumer.IsWritable() && consumer.AvailableBytes() < salt.size()) {
producer->Close();
return;
}
std::this_thread::yield();
}
auto saltSpan = consumer.Span(salt.size());
if (!saltSpan.has_value()) {
producer->Close();
return;
}
std::copy_n(reinterpret_cast<const uint8_t*>(saltSpan.value().data()), salt.size(), salt.data());

while (consumer.AvailableBytes() < iv.size()) {
if (!consumer.IsWritable() && consumer.AvailableBytes() < iv.size()) {
producer->Close();
return;
}
std::this_thread::yield();
}
auto ivSpan = consumer.Span(iv.size());
if (!ivSpan.has_value()) {
producer->Close();
return;
}
std::copy_n(reinterpret_cast<const uint8_t*>(ivSpan.value().data()), iv.size(), iv.data());

CryptoPP::SecByteBlock key(CryptoPP::Serpent::DEFAULT_KEYLENGTH);
CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
password.size(), salt, salt.size(), 10000);

CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption decryption(key, key.size(), iv);
std::vector<uint8_t> decryptedChunk;
std::vector<std::byte> batchBuffer;
batchBuffer.reserve(chunkSize * 2);

while (!consumer.EoF()) {
size_t availableBytes = consumer.AvailableBytes();
if (availableBytes == 0) {
std::this_thread::yield();
continue;
}

size_t bytesToRead = std::min(availableBytes, chunkSize);
auto spanResult = consumer.Span(bytesToRead);
if (!spanResult.has_value()) {
producer->Close();
return;
}

const auto& encryptedSpan = spanResult.value();
decryptedChunk.clear();

CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size(), true,
new CryptoPP::StreamTransformationFilter(decryption,
new CryptoPP::VectorSink(decryptedChunk)));

for (size_t i = 0; i < decryptedChunk.size(); ++i) {
batchBuffer.push_back(static_cast<std::byte>(decryptedChunk[i]));
}

if (batchBuffer.size() >= chunkSize) {
(void)producer->Write(std::move(batchBuffer));
batchBuffer.clear();
batchBuffer.reserve(chunkSize * 2);
consumer.Clean();
}
}
if (!batchBuffer.empty()) {
(void)producer->Write(std::move(batchBuffer));
}
producer->Close();
} catch (...) {
producer->Close();
}
}).detach();

return producer->Consumer();
}

ExpectedCryptoString Serpent::RandomPassword(const size_t& passwordSize) noexcept {
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
