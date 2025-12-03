#include <StormByte/crypto/implementation/hash/blake2s.hxx>

#include <algorithm>
#include <blake2.h>
#include <hex.h>
#include <vector>
#include <thread>
#include <span>

using namespace StormByte::Crypto::Implementation::Hash;

namespace {
	ExpectedHashString ComputeBlake2s(std::span<const std::byte> dataSpan) noexcept {
		try {
			std::vector<uint8_t> data(dataSpan.size());
			std::transform(dataSpan.begin(), dataSpan.end(), data.begin(),
						[](std::byte b) { return static_cast<uint8_t>(b); });

			CryptoPP::BLAKE2s hash;
			std::string hashOutput;

			CryptoPP::StringSource ss(data.data(), data.size(), true,
									new CryptoPP::HashFilter(hash,
									new CryptoPP::HexEncoder(
										new CryptoPP::StringSink(hashOutput))));

			return hashOutput;
		} catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>("Blake2s hashing failed: {}", e.what());
		}
	}
}

ExpectedHashString Blake2s::Hash(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return ComputeBlake2s(dataSpan);
}

ExpectedHashString Blake2s::Hash(const Buffer::FIFO& buffer) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(buffer).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return ComputeBlake2s(dataSpan);
}

StormByte::Buffer::Consumer Blake2s::Hash(Buffer::Consumer consumer) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer]() mutable {
		try {
			CryptoPP::BLAKE2s hash;
			std::string hashOutput;
			CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashOutput));

			constexpr size_t chunkSize = 4096;
			std::vector<uint8_t> chunkBuffer(chunkSize);

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
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					producer->Close();
					return;
				}

				const auto& inputData = readResult.value();
				hash.Update(reinterpret_cast<const CryptoPP::byte*>(inputData.data()), inputData.size());
			}
			// Finalize the hash
			hash.Final(reinterpret_cast<CryptoPP::byte*>(chunkBuffer.data()));
			encoder.Put(chunkBuffer.data(), hash.DigestSize());
			encoder.MessageEnd();

			std::vector<std::byte> byteData;
			byteData.reserve(hashOutput.size());
			for (size_t i = 0; i < hashOutput.size(); ++i) {
				byteData.push_back(static_cast<std::byte>(hashOutput[i]));
			}
			producer->Write(byteData);
			producer->Close();
		} catch (...) {
			producer->Close();
		}
	}).detach();

	return producer->Consumer();
}