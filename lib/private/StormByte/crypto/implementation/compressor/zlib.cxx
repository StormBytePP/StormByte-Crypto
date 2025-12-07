#include <StormByte/crypto/implementation/compressor/zlib.hxx>

#include <algorithm>
#include <cryptopp/zlib.h>
#include <cryptlib.h>
#include <filters.h>
#include <stdexcept>
#include <thread>
#include <vector>
#include <span>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
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

			// Create Buffer and write data
			FIFO buffer;
			(void)buffer.Write(std::move(compressedString));
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

			// Create Buffer and write data
			FIFO buffer;
			(void)buffer.Write(std::move(decompressedString));
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

ExpectedCompressorBuffer Zlib::Compress(const FIFO& input) noexcept {
	DataType data;
	auto read_ok = input.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(CompressorException("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return CompressHelper(dataSpan);
}

Consumer Zlib::Compress(Consumer consumer) noexcept {
	Producer producer;

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
				DataType data;
				auto read_ok = consumer.Extract(bytesToRead, data);
				if (!read_ok.has_value()) {
					producer.SetError();
					return;
				}

				compressor.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
				compressor.Flush(true);
				if (!compressedString.empty()) {
					(void)producer.Write(std::move(compressedString));
					compressedString.clear();
				}
			}
			compressor.MessageEnd();
			if (!compressedString.empty()) {
				(void)producer.Write(std::move(compressedString));
			}
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

// Public Decompress Methods
ExpectedCompressorBuffer Zlib::Decompress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecompressHelper(dataSpan);
}

ExpectedCompressorBuffer Zlib::Decompress(const FIFO& input) noexcept {
	DataType data;
	auto read_ok = input.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(CompressorException("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return DecompressHelper(dataSpan);
}

Consumer Zlib::Decompress(Consumer consumer) noexcept {
	Producer producer;

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
				DataType data;
				auto read_ok = consumer.Extract(bytesToRead, data);
				if (!read_ok.has_value()) {
					producer.SetError();
					return;
				}

				decompressor.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
				decompressor.Flush(true);
				if (!decompressedString.empty()) {
					(void)producer.Write(std::move(decompressedString));
					decompressedString.clear();
				}
			}
			decompressor.MessageEnd();
			if (!decompressedString.empty()) {
				(void)producer.Write(std::move(decompressedString));
			}
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}
