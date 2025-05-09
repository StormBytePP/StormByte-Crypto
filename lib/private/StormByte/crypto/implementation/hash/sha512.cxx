#include <StormByte/crypto/implementation/hash/sha512.hxx>

#include <hex.h>
#include <format>
#include <future>
#include <sha.h>
#include <vector>
#include <thread>

using namespace StormByte::Crypto::Implementation::Hash;

namespace {
	/**
	 * @brief Helper function to compute SHA-512 hash.
	 * @param dataSpan The input data as std::span<const std::byte>.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	ExpectedHashFutureString ComputeSHA512(std::span<const std::byte> dataSpan) noexcept {
		try {
			// Convert std::span<std::byte> to std::vector<uint8_t>
			std::vector<uint8_t> data;
			std::transform(dataSpan.begin(), dataSpan.end(), std::back_inserter(data),
						[](std::byte b) { return static_cast<uint8_t>(b); });

			// Compute SHA-512 hash
			CryptoPP::SHA512 hash;
			std::string hashOutput;

			CryptoPP::StringSource ss(data.data(), data.size(), true,
									new CryptoPP::HashFilter(hash,
									new CryptoPP::HexEncoder(
										new CryptoPP::StringSink(hashOutput))));

			return hashOutput;
		} catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>("SHA-512 hashing failed: {}", e.what());
		}
	}
}

ExpectedHashFutureString SHA512::Hash(const std::string& input) noexcept {
	// Create a std::span<std::byte> from the input string
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());

	// Use the common helper function to compute the hash
	return ComputeSHA512(dataSpan);
}

ExpectedHashFutureString SHA512::Hash(const StormByte::Buffer::Simple& buffer) noexcept {
	// Use Buffer's Data() method to get std::span<std::byte>
	auto dataSpan = buffer.Data();

	// Use the common helper function to compute the hash
	return ComputeSHA512(dataSpan);
}

StormByte::Buffer::Consumer SHA512::Hash(const Buffer::Consumer consumer) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer]() {
		try {
			CryptoPP::SHA512 hash;
			std::string hashOutput; // Create a string to hold the hash output
			CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashOutput)); // Pass the string to StringSink

			constexpr size_t chunkSize = 4096;
			std::vector<uint8_t> chunkBuffer(chunkSize);

			while (consumer.IsReadable() && !consumer.IsEoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					*producer << StormByte::Buffer::Status::Error;
					return;
				}

				const auto& inputData = readResult.value();
				hash.Update(reinterpret_cast<const CryptoPP::byte*>(inputData.data()), inputData.size());
			}
			if (consumer.IsReadable()) {
				// Finalize the hash
				hash.Final(reinterpret_cast<CryptoPP::byte*>(chunkBuffer.data()));
				encoder.Put(chunkBuffer.data(), hash.DigestSize());
				encoder.MessageEnd();

				*producer << StormByte::Buffer::Simple(hashOutput.data(), hashOutput.size());
			}
			*producer << consumer.Status(); // Update status (EOF or Error)
		} catch (...) {
			*producer << StormByte::Buffer::Status::Error;
		}
	}).detach();

	return producer->Consumer();
}