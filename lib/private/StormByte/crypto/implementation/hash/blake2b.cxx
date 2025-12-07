#include <StormByte/crypto/implementation/hash/blake2b.hxx>

#include <algorithm>
#include <blake2.h>
#include <hex.h>
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
	ExpectedHashString ComputeBlake2b(std::span<const std::byte> dataSpan) noexcept {
		try {
			std::vector<uint8_t> data(dataSpan.size());
			std::transform(
				dataSpan.begin(),
				dataSpan.end(),
				data.begin(),
				[](std::byte b) { return static_cast<uint8_t>(b); }
			);

			CryptoPP::BLAKE2b hash;
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
			return Unexpected(HasherException("Blake2b hashing failed: {}", e.what()));
		}
	}
}

ExpectedHashString Blake2b::Hash(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return ComputeBlake2b(dataSpan);
}

ExpectedHashString Blake2b::Hash(const FIFO& buffer) noexcept {
	DataType data;
	auto read_ok = buffer.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(HasherException("Failed to extract data from buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return ComputeBlake2b(dataSpan);
}

Consumer Blake2b::Hash(Consumer consumer) noexcept {
	Producer producer;

	std::thread([consumer, producer]() mutable {
		try {
			CryptoPP::BLAKE2b hash;
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