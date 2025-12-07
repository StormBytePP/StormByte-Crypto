#include <StormByte/crypto/implementation/hash/sha3.hxx>

#include <algorithm>
#include <hex.h>
#include <format>
#include <sha3.h>
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
	ExpectedHashString ComputeSHA3_256(std::span<const std::byte> dataSpan) noexcept {
		try {
			std::vector<uint8_t> data;
			std::transform(
				dataSpan.begin(),
				dataSpan.end(),
				std::back_inserter(data),
				[](std::byte b) { return static_cast<uint8_t>(b); }
			);

			CryptoPP::SHA3_256 hash;
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
			return Unexpected(HasherException("SHA3-256 hashing failed: {}", e.what()));
		}
	}

	ExpectedHashString ComputeSHA3_512(std::span<const std::byte> dataSpan) noexcept {
		try {
			std::vector<uint8_t> data;
			std::transform(
				dataSpan.begin(),
				dataSpan.end(),
				std::back_inserter(data),
				[](std::byte b) { return static_cast<uint8_t>(b); }
			);

			CryptoPP::SHA3_512 hash;
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
		return Unexpected(HasherException("SHA3-512 hashing failed: {}", e.what()));
		}
	}
}

// SHA3-256
ExpectedHashString SHA3_256::Hash(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return ComputeSHA3_256(dataSpan);
}

ExpectedHashString SHA3_256::Hash(const FIFO& buffer) noexcept {
	DataType data;
	auto read_ok = buffer.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(HasherException("Failed to extract data from buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return ComputeSHA3_256(dataSpan);
}

Consumer SHA3_256::Hash(Consumer consumer) noexcept {
	Producer producer;

	std::thread([consumer, producer]() mutable {
		try {
			CryptoPP::SHA3_256 hash;
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

// SHA3-512
ExpectedHashString SHA3_512::Hash(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return ComputeSHA3_512(dataSpan);
}

ExpectedHashString SHA3_512::Hash(const FIFO& buffer) noexcept {
	DataType data;
	auto read_ok = buffer.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(HasherException("Failed to extract data from buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return ComputeSHA3_512(dataSpan);
}

Consumer SHA3_512::Hash(Consumer consumer) noexcept {
	Producer producer;

	std::thread([consumer, producer]() mutable {
		try {
			CryptoPP::SHA3_512 hash;
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
