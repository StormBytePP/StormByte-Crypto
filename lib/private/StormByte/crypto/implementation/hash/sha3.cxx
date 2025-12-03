#include <StormByte/crypto/implementation/hash/sha3.hxx>

#include <algorithm>
#include <hex.h>
#include <format>
#include <sha3.h>
#include <vector>
#include <thread>
#include <span>

using namespace StormByte::Crypto::Implementation::Hash;

namespace {
ExpectedHashString ComputeSHA3_256(std::span<const std::byte> dataSpan) noexcept {
try {
std::vector<uint8_t> data;
std::transform(dataSpan.begin(), dataSpan.end(), std::back_inserter(data),
[](std::byte b) { return static_cast<uint8_t>(b); });

CryptoPP::SHA3_256 hash;
std::string hashOutput;

CryptoPP::StringSource ss(data.data(), data.size(), true,
new CryptoPP::HashFilter(hash,
new CryptoPP::HexEncoder(
new CryptoPP::StringSink(hashOutput))));

return hashOutput;
} catch (const std::exception& e) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("SHA3-256 hashing failed: {}", e.what());
}
}

ExpectedHashString ComputeSHA3_512(std::span<const std::byte> dataSpan) noexcept {
try {
std::vector<uint8_t> data;
std::transform(dataSpan.begin(), dataSpan.end(), std::back_inserter(data),
[](std::byte b) { return static_cast<uint8_t>(b); });

CryptoPP::SHA3_512 hash;
std::string hashOutput;

CryptoPP::StringSource ss(data.data(), data.size(), true,
new CryptoPP::HashFilter(hash,
new CryptoPP::HexEncoder(
new CryptoPP::StringSink(hashOutput))));

return hashOutput;
} catch (const std::exception& e) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("SHA3-512 hashing failed: {}", e.what());
}
}
}

// SHA3-256
ExpectedHashString SHA3_256::Hash(const std::string& input) noexcept {
std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
return ComputeSHA3_256(dataSpan);
}

ExpectedHashString SHA3_256::Hash(const StormByte::Buffer::FIFO& buffer) noexcept {
auto data = const_cast<StormByte::Buffer::FIFO&>(buffer).Extract(0);
if (!data.has_value()) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from buffer");
}
std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
return ComputeSHA3_256(dataSpan);
}

StormByte::Buffer::Consumer SHA3_256::Hash(Buffer::Consumer consumer) noexcept {
SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

std::thread([consumer, producer]() mutable {
try {
CryptoPP::SHA3_256 hash;
std::string hashOutput;
CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashOutput));

constexpr size_t chunkSize = 4096;
std::vector<uint8_t> chunkBuffer(chunkSize);
size_t chunksProcessed = 0;

while (!consumer.EoF()) {
size_t availableBytes = consumer.AvailableBytes();
if (availableBytes == 0) {
if (!consumer.IsWritable()) {
break;
}
std::this_thread::yield();
continue;
}

size_t bytesToRead = std::min(availableBytes, chunkSize);
auto spanResult = consumer.Span(bytesToRead);
if (!spanResult.has_value()) {
producer->Close();
return;
}

const auto& inputSpan = spanResult.value();
hash.Update(reinterpret_cast<const CryptoPP::byte*>(inputSpan.data()), inputSpan.size());

if (++chunksProcessed % 16 == 0) {
consumer.Clean();
}
}

hash.Final(reinterpret_cast<CryptoPP::byte*>(chunkBuffer.data()));
encoder.Put(chunkBuffer.data(), hash.DigestSize());
encoder.MessageEnd();

std::vector<std::byte> byteData;
byteData.reserve(hashOutput.size());
for (size_t i = 0; i < hashOutput.size(); ++i) {
byteData.push_back(static_cast<std::byte>(hashOutput[i]));
}
(void)producer->Write(byteData);
producer->Close();
} catch (...) {
producer->Close();
}
}).detach();

return producer->Consumer();
}

// SHA3-512
ExpectedHashString SHA3_512::Hash(const std::string& input) noexcept {
std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
return ComputeSHA3_512(dataSpan);
}

ExpectedHashString SHA3_512::Hash(const StormByte::Buffer::FIFO& buffer) noexcept {
auto data = const_cast<StormByte::Buffer::FIFO&>(buffer).Extract(0);
if (!data.has_value()) {
return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from buffer");
}
std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
return ComputeSHA3_512(dataSpan);
}

StormByte::Buffer::Consumer SHA3_512::Hash(Buffer::Consumer consumer) noexcept {
SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

std::thread([consumer, producer]() mutable {
try {
CryptoPP::SHA3_512 hash;
std::string hashOutput;
CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashOutput));

constexpr size_t chunkSize = 4096;
std::vector<uint8_t> chunkBuffer(chunkSize);
size_t chunksProcessed = 0;

while (!consumer.EoF()) {
size_t availableBytes = consumer.AvailableBytes();
if (availableBytes == 0) {
if (!consumer.IsWritable()) {
break;
}
std::this_thread::yield();
continue;
}

size_t bytesToRead = std::min(availableBytes, chunkSize);
auto spanResult = consumer.Span(bytesToRead);
if (!spanResult.has_value()) {
producer->Close();
return;
}

const auto& inputSpan = spanResult.value();
hash.Update(reinterpret_cast<const CryptoPP::byte*>(inputSpan.data()), inputSpan.size());

if (++chunksProcessed % 16 == 0) {
consumer.Clean();
}
}

hash.Final(reinterpret_cast<CryptoPP::byte*>(chunkBuffer.data()));
encoder.Put(chunkBuffer.data(), hash.DigestSize());
encoder.MessageEnd();

std::vector<std::byte> byteData;
byteData.reserve(hashOutput.size());
for (size_t i = 0; i < hashOutput.size(); ++i) {
byteData.push_back(static_cast<std::byte>(hashOutput[i]));
}
(void)producer->Write(byteData);
producer->Close();
} catch (...) {
producer->Close();
}
}).detach();

return producer->Consumer();
}
