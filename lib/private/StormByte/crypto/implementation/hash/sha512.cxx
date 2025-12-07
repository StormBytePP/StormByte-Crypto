#include <StormByte/crypto/implementation/hash/sha512.hxx>

#include <algorithm>
#include <hex.h>
#include <format>
#include <sha.h>
#include <vector>
#include <thread>
#include <span>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
using namespace StormByte::Crypto::Implementation::Hash;

namespace {
	/**
	 * @brief Helper function to compute SHA-512 hash.
	 * @param dataSpan The input data as std::span<const std::byte>.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	ExpectedHashString ComputeSHA512(std::span<const std::byte> dataSpan) noexcept {
		try {
			// Convert std::span<std::byte> to std::vector<uint8_t>
			std::vector<uint8_t> data;
			std::transform(
				dataSpan.begin(),
				dataSpan.end(),
				std::back_inserter(data),
				[](std::byte b) { return static_cast<uint8_t>(b); }
			);

			// Compute SHA-512 hash
			CryptoPP::SHA512 hash;
			std::string hashOutput;

			CryptoPP::StringSource ss(
				data.data(),
				data.size(),
				true,
				new CryptoPP::HashFilter(
					hash,
					new CryptoPP::HexEncoder(new CryptoPP::StringSink(hashOutput))
				)
			);

			return hashOutput;
		} catch (const std::exception& e) {
			return Unexpected(HasherException("SHA-512 hashing failed: {}", e.what()));
		}
	}
}

ExpectedHashString SHA512::Hash(const std::string& input) noexcept {
	// Create a std::span<std::byte> from the input string
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());

	// Use the common helper function to compute the hash
	return ComputeSHA512(dataSpan);
}

ExpectedHashString SHA512::Hash(const FIFO& buffer) noexcept {
	DataType data;
	auto read_ok = buffer.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(HasherException("Failed to extract data from buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return ComputeSHA512(dataSpan);
}

Consumer SHA512::Hash(Consumer consumer) noexcept {
	Producer producer;

	std::thread([consumer, producer]() mutable {
		try {
			CryptoPP::SHA512 hash;
			std::string hashOutput;
			CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashOutput));

			constexpr size_t chunkSize = 4096;
			std::vector<uint8_t> chunkBuffer(chunkSize);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto spanResult = consumer.Extract(bytesToRead, data);
				if (!spanResult.has_value()) {
					producer.SetError();
					return;
				}
				
				hash.Update(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
			}
			// Finalize the hash
			hash.Final(reinterpret_cast<CryptoPP::byte*>(chunkBuffer.data()));
			encoder.Put(chunkBuffer.data(), hash.DigestSize());
			encoder.MessageEnd();

			(void)producer.Write(std::move(hashOutput));
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}