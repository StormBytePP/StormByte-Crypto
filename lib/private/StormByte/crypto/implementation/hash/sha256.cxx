#include <StormByte/crypto/implementation/hash/sha256.hxx>

#include <algorithm>
#include <hex.h>
#include <format>
#include <sha.h>
#include <vector>
#include <thread>
#include <span>

using namespace StormByte::Crypto::Implementation::Hash;

namespace {
	/**
	 * @brief Helper function to compute SHA-256 hash.
	 * @param dataSpan The input data as std::span<const std::byte>.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	ExpectedHashString ComputeSHA256(std::span<const std::byte> dataSpan) noexcept {
		try {
			// Convert std::span<std::byte> to std::vector<uint8_t>
			std::vector<uint8_t> data;
			std::transform(dataSpan.begin(), dataSpan.end(), std::back_inserter(data),
						[](std::byte b) { return static_cast<uint8_t>(b); });

			// Compute SHA-256 hash
			CryptoPP::SHA256 hash;
			std::string hashOutput;

			CryptoPP::StringSource ss(data.data(), data.size(), true,
									new CryptoPP::HashFilter(hash,
									new CryptoPP::HexEncoder(
										new CryptoPP::StringSink(hashOutput))));

			return hashOutput;
		} catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>("SHA-256 hashing failed: {}", e.what());
		}
	}
}

ExpectedHashString SHA256::Hash(const std::string& input) noexcept {
	// Create a std::span<std::byte> from the input string
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());

	// Use the common helper function to compute the hash
	return ComputeSHA256(dataSpan);
}

ExpectedHashString SHA256::Hash(const StormByte::Buffer::FIFO& buffer) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(buffer).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return ComputeSHA256(dataSpan);
}

StormByte::Buffer::Consumer SHA256::Hash(Buffer::Consumer consumer) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer]() mutable {
		try {
		CryptoPP::SHA256 hash;
		std::string hashOutput;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashOutput));

		constexpr size_t chunkSize = 4096;
		std::vector<uint8_t> chunkBuffer(chunkSize);
		[[maybe_unused]] size_t chunksProcessed = 0;

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
				// Use Span for zero-copy read
			auto spanResult = consumer.Span(bytesToRead);
				if (!spanResult.has_value()) {
					producer->Close();
					return;
				}

				const auto& inputSpan = spanResult.value();
				hash.Update(reinterpret_cast<const CryptoPP::byte*>(inputSpan.data()), inputSpan.size());
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
