#include <StormByte/crypto/implementation/compressor/zlib.hxx>

#include <algorithm>
#include <cryptopp/zlib.h>
#include <cryptlib.h>
#include <filters.h>
#include <stdexcept>
#include <thread>
#include <vector>
#include <span>

using namespace StormByte::Crypto::Implementation::Compressor;

namespace {
	ExpectedCompressorBuffer CompressHelper(std::span<const std::byte> inputData) noexcept {
		try {
			std::string compressedString;

			// Use Crypto++'s Zlib for compression (Deflate)
			CryptoPP::StringSource ss(
				reinterpret_cast<const uint8_t*>(inputData.data()), inputData.size_bytes(), true,
				new CryptoPP::ZlibCompressor(
					new CryptoPP::StringSink(compressedString), CryptoPP::ZlibCompressor::MAX_DEFLATE_LEVEL));

			// Convert the compressed string to std::vector<std::byte>
			std::vector<std::byte> compressedData(compressedString.size());
			std::transform(compressedString.begin(), compressedString.end(), compressedData.begin(),
				[](char c) { return static_cast<std::byte>(c); });

			// Create Buffer and write data
			StormByte::Buffer::FIFO buffer;
			(void)buffer.Write(compressedData);
			return buffer;
		}
		catch (const CryptoPP::Exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}

	ExpectedCompressorBuffer DecompressHelper(std::span<const std::byte> compressedData) noexcept {
		try {
			std::string decompressedString;

			// Use Crypto++'s Zlib for decompression (Inflate)
			CryptoPP::StringSource ss(
				reinterpret_cast<const uint8_t*>(compressedData.data()), compressedData.size_bytes(), true,
				new CryptoPP::ZlibDecompressor(new CryptoPP::StringSink(decompressedString)));

			// Convert the decompressed string to std::vector<std::byte>
			std::vector<std::byte> decompressedData(decompressedString.size());
			std::transform(decompressedString.begin(), decompressedString.end(), decompressedData.begin(),
				[](char c) { return static_cast<std::byte>(c); });

			// Create Buffer and write data
			StormByte::Buffer::FIFO buffer;
			(void)buffer.Write(decompressedData);
			return buffer;
		}
		catch (const CryptoPP::Exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}
}

// Public Compress Methods
ExpectedCompressorBuffer Zlib::Compress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return CompressHelper(dataSpan);
}

ExpectedCompressorBuffer Zlib::Compress(const StormByte::Buffer::FIFO& input) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return CompressHelper(dataSpan);
}

StormByte::Buffer::Consumer Zlib::Compress(Buffer::Consumer consumer) noexcept {
	StormByte::Buffer::Producer producer;

	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			std::string compressedString;
			CryptoPP::ZlibCompressor compressor(new CryptoPP::StringSink(compressedString), CryptoPP::ZlibCompressor::MAX_DEFLATE_LEVEL);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					if (!consumer.IsWritable()) break;
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto spanResult = consumer.Extract(bytesToRead);
				if (!spanResult.has_value()) { producer.Close(); return; }

				const auto& inputSpan = spanResult.value();
				if (inputSpan.empty()) continue;

				compressor.Put(reinterpret_cast<const uint8_t*>(inputSpan.data()), inputSpan.size());
				compressor.Flush(true);
				if (!compressedString.empty()) {
					std::vector<std::byte> chunkData(compressedString.size());
					std::transform(compressedString.begin(), compressedString.end(), chunkData.begin(), [](char c) { return static_cast<std::byte>(c); });
					(void)producer.Write(chunkData);
					compressedString.clear();
				}
			}
			compressor.MessageEnd();
			if (!compressedString.empty()) {
				std::vector<std::byte> byteData(compressedString.size());
				std::transform(compressedString.begin(), compressedString.end(), byteData.begin(), [](char c) { return static_cast<std::byte>(c); });
				(void)producer.Write(byteData);
			}
			producer.Close();
		} catch (...) {
			producer.Close();
		}
	}).detach();

	return producer.Consumer();
}

// Public Decompress Methods
ExpectedCompressorBuffer Zlib::Decompress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecompressHelper(dataSpan);
}

ExpectedCompressorBuffer Zlib::Decompress(const StormByte::Buffer::FIFO& input) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return DecompressHelper(dataSpan);
}

StormByte::Buffer::Consumer Zlib::Decompress(Buffer::Consumer consumer) noexcept {
	StormByte::Buffer::Producer producer;

	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			std::string decompressedString;
			CryptoPP::ZlibDecompressor decompressor(new CryptoPP::StringSink(decompressedString));

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					if (!consumer.IsWritable()) break;
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto spanResult = consumer.Extract(bytesToRead);
				if (!spanResult.has_value()) { producer.Close(); return; }

				const auto& compressedSpan = spanResult.value();
				if (compressedSpan.empty()) continue;

				decompressor.Put(reinterpret_cast<const uint8_t*>(compressedSpan.data()), compressedSpan.size());
				decompressor.Flush(true);
				if (!decompressedString.empty()) {
					std::vector<std::byte> chunkData(decompressedString.size());
					std::transform(decompressedString.begin(), decompressedString.end(), chunkData.begin(), [](char c) { return static_cast<std::byte>(c); });
					(void)producer.Write(chunkData);
					decompressedString.clear();
				}
			}
			decompressor.MessageEnd();
			if (!decompressedString.empty()) {
				std::vector<std::byte> byteData(decompressedString.size());
				std::transform(decompressedString.begin(), decompressedString.end(), byteData.begin(), [](char c) { return static_cast<std::byte>(c); });
				(void)producer.Write(byteData);
			}
			producer.Close();
		} catch (...) {
			producer.Close();
		}
	}).detach();

	return producer.Consumer();
}
