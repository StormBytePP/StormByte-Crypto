#include <StormByte/crypto/implementation/hash/blake2b.hxx>
#include <blake2.h>
#include <hex.h>
#include <future>
#include <vector>
#include <thread>

using namespace StormByte::Crypto::Implementation::Hash;

namespace {
	ExpectedHashFutureString ComputeBlake2b(std::span<const std::byte> dataSpan) noexcept {
		try {
			std::vector<uint8_t> data(dataSpan.size());
			std::transform(dataSpan.begin(), dataSpan.end(), data.begin(),
						[](std::byte b) { return static_cast<uint8_t>(b); });

			CryptoPP::BLAKE2b hash;
			std::string hashOutput;

			CryptoPP::StringSource ss(data.data(), data.size(), true,
									new CryptoPP::HashFilter(hash,
									new CryptoPP::HexEncoder(
										new CryptoPP::StringSink(hashOutput))));

			return hashOutput;
		} catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>("Blake2b hashing failed: {}", e.what());
		}
	}
}

ExpectedHashFutureString Blake2b::Hash(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return ComputeBlake2b(dataSpan);
}

ExpectedHashFutureString Blake2b::Hash(const Buffer::Simple& buffer) noexcept {
	return ComputeBlake2b(buffer.Data());
}

StormByte::Buffer::Consumer Blake2b::Hash(const Buffer::Consumer consumer) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer]() {
		try {
			CryptoPP::BLAKE2b hash;
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
					break;
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