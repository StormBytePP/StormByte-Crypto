#include <StormByte/crypto/implementation/compressor/bzip2.hxx>

#include <algorithm>
#include <bzlib.h>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <span>
#include <thread>
#include <vector>

using namespace StormByte::Crypto::Implementation::Compressor;

namespace {
	ExpectedCompressorBuffer CompressHelper(std::span<const std::byte> inputData, int blockSize = 9) noexcept {
		try {
			unsigned int compressedSize = static_cast<unsigned int>(std::ceil(inputData.size_bytes() * 1.01 + 600));
			std::vector<uint8_t> compressedData(compressedSize);

			if (BZ2_bzBuffToBuffCompress(reinterpret_cast<char*>(compressedData.data()), &compressedSize,
				const_cast<char*>(reinterpret_cast<const char*>(inputData.data())),
				static_cast<unsigned int>(inputData.size_bytes()), blockSize, 0, 30) != BZ_OK) {
				return StormByte::Unexpected<StormByte::Crypto::Exception>("BZip2 compression failed");
			}

		compressedData.resize(compressedSize);
		
		// Convert to std::byte vector and create FIFO
		std::vector<std::byte> byteData(compressedSize);
		std::transform(compressedData.begin(), compressedData.end(), byteData.begin(),
			[](uint8_t b) { return static_cast<std::byte>(b); });
		
		StormByte::Buffer::FIFO buffer;
		buffer.Write(byteData);
		return buffer;
		}
		catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}

	ExpectedCompressorBuffer DecompressHelper(std::span<const std::byte> compressedData) noexcept {
		try {
			// Allocate a buffer with an initial size
			std::vector<uint8_t> decompressedData(4096); // Start with a reasonable size
			unsigned int decompressedSize = static_cast<unsigned int>(decompressedData.size());

			// Attempt decompression
			int result = BZ2_bzBuffToBuffDecompress(
				reinterpret_cast<char*>(decompressedData.data()), &decompressedSize,
				const_cast<char*>(reinterpret_cast<const char*>(compressedData.data())),
				static_cast<unsigned int>(compressedData.size_bytes()), 0, 0);

			// If the buffer was too small, resize and retry
			while (result == BZ_OUTBUFF_FULL) {
				decompressedData.resize(decompressedData.size() * 2); // Double the buffer size
				decompressedSize = static_cast<unsigned int>(decompressedData.size());

				result = BZ2_bzBuffToBuffDecompress(
					reinterpret_cast<char*>(decompressedData.data()), &decompressedSize,
					const_cast<char*>(reinterpret_cast<const char*>(compressedData.data())),
					static_cast<unsigned int>(compressedData.size_bytes()), 0, 0);
			}

			if (result != BZ_OK) {
				return StormByte::Unexpected<StormByte::Crypto::Exception>("BZip2 decompression failed");
			}

		// Resize the buffer to the actual decompressed size
		decompressedData.resize(decompressedSize);
		
		// Convert to std::byte vector and create FIFO
		std::vector<std::byte> byteData(decompressedSize);
		std::transform(decompressedData.begin(), decompressedData.end(), byteData.begin(),
			[](uint8_t b) { return static_cast<std::byte>(b); });
		
		StormByte::Buffer::FIFO buffer;
		buffer.Write(byteData);
		return buffer;
		} catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}
}

// Public Compress Methods
ExpectedCompressorBuffer BZip2::Compress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return CompressHelper(dataSpan);
}

ExpectedCompressorBuffer BZip2::Compress(const StormByte::Buffer::FIFO& input) noexcept {
	// Extract all data from FIFO to a span
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return CompressHelper(dataSpan);
}

StormByte::Buffer::Consumer BZip2::Compress(Buffer::Consumer consumer) noexcept {
	// Create a producer buffer to store the compressed data
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	// Launch a detached thread to handle compression
	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096; // Define the chunk size for reading from the consumer
			std::vector<uint8_t> compressedBuffer(chunkSize * 2); // Allocate a larger buffer for compressed data

			while (!consumer.EoF()) {
				// Check how many bytes are available in the consumer
				size_t availableBytes = consumer.AvailableBytes();

				if (availableBytes == 0) {
					// Wait for more data to become available
					std::this_thread::yield();
					continue;
				}

				// Read the available bytes (up to chunkSize)
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					// If reading fails, close the producer
					producer->Close();
					break;
				}

				const auto& inputData = readResult.value();

				if (inputData.empty()) {
					continue; // Try again
				}

				// Compress the chunk
				unsigned int compressedSize = static_cast<unsigned int>(std::ceil(inputData.size() * 1.01 + 600));
				compressedBuffer.resize(compressedSize);

				int result = BZ2_bzBuffToBuffCompress(
					reinterpret_cast<char*>(compressedBuffer.data()), &compressedSize,
					const_cast<char*>(reinterpret_cast<const char*>(inputData.data())),
					static_cast<unsigned int>(inputData.size()), 9, 0, 30);

				if (result != BZ_OK) {
					// Compression failed, close the producer
					producer->Close();
					return;
				}

				// Resize the compressed buffer to the actual size
				compressedBuffer.resize(compressedSize);

				// Write the compressed data to the producer
				std::vector<std::byte> byteData(compressedSize);
				std::transform(compressedBuffer.begin(), compressedBuffer.end(), byteData.begin(),
					[](uint8_t b) { return static_cast<std::byte>(b); });
				producer->Write(byteData);
			}
			producer->Close(); // Mark compression complete
		} catch (...) {
			// Handle any unexpected exceptions and close the producer
			producer->Close();
		}
	}).detach();

	// Return a consumer buffer for the producer
	return producer->Consumer();
}

// Public Decompress Methods
ExpectedCompressorBuffer BZip2::Decompress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecompressHelper(dataSpan);
}

ExpectedCompressorBuffer BZip2::Decompress(const StormByte::Buffer::FIFO& input) noexcept {
	// Extract all data from FIFO to a span
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return DecompressHelper(dataSpan);
}

StormByte::Buffer::Consumer BZip2::Decompress(Buffer::Consumer consumer) noexcept {
	// Create a producer buffer to store the decompressed data
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	// Launch a detached thread to handle decompression
	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096; // Define the chunk size for reading from the consumer
			std::vector<uint8_t> decompressedBuffer(chunkSize * 2); // Start with a larger buffer for decompressed data

			while (!consumer.EoF()) {
				// Check how many bytes are available in the consumer
				size_t availableBytes = consumer.AvailableBytes();

				if (availableBytes == 0) {
					// Wait for more data to become available
					std::this_thread::yield();
					continue;
				}

				// Read the available bytes (up to chunkSize)
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					// If reading fails, close the producer
					producer->Close();
					return;
				}

				const auto& compressedData = readResult.value();
				if (compressedData.empty()) {
					continue; // Try again
				}

				// Decompress the chunk
				unsigned int decompressedSize = static_cast<unsigned int>(decompressedBuffer.size());
				int result = BZ2_bzBuffToBuffDecompress(
					reinterpret_cast<char*>(decompressedBuffer.data()), &decompressedSize,
					const_cast<char*>(reinterpret_cast<const char*>(compressedData.data())),
					static_cast<unsigned int>(compressedData.size()), 0, 0);

				// If the buffer was too small, resize and retry
				while (result == BZ_OUTBUFF_FULL) {
					decompressedBuffer.resize(decompressedBuffer.size() * 2);
					decompressedSize = static_cast<unsigned int>(decompressedBuffer.size());

					result = BZ2_bzBuffToBuffDecompress(
						reinterpret_cast<char*>(decompressedBuffer.data()), &decompressedSize,
						const_cast<char*>(reinterpret_cast<const char*>(compressedData.data())),
						static_cast<unsigned int>(compressedData.size()), 0, 0);
				}

				if (result != BZ_OK) {
					// Decompression failed, close the producer
					producer->Close();
					return;
				}

				// Resize the decompressed buffer to the actual size
				decompressedBuffer.resize(decompressedSize);

				// Write the decompressed data to the producer
				std::vector<std::byte> byteData(decompressedSize);
				std::transform(decompressedBuffer.begin(), decompressedBuffer.end(), byteData.begin(),
					[](uint8_t b) { return static_cast<std::byte>(b); });
				producer->Write(byteData);
			}
			producer->Close(); // Mark decompression complete
		} catch (...) {
			// Handle any unexpected exceptions and close the producer
			producer->Close();
		}
	}).detach();

	// Return a consumer buffer for the producer
	return producer->Consumer();
}
