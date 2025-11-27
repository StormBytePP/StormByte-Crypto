#include <StormByte/crypto/implementation/compressor/gzip.hxx>

#include <gzip.h>
#include <cryptlib.h>
#include <filters.h>
#include <future>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace StormByte::Crypto::Implementation::Compressor;

namespace {
	ExpectedCompressorBuffer CompressHelper(std::span<const std::byte> inputData) noexcept {
		try {
			std::string compressedString;

			// Use Crypto++'s Gzip for compression
			CryptoPP::StringSource ss(
				reinterpret_cast<const uint8_t*>(inputData.data()), inputData.size_bytes(), true,
				new CryptoPP::Gzip(
					new CryptoPP::StringSink(compressedString), CryptoPP::Gzip::MAX_DEFLATE_LEVEL));

		// Convert the compressed string to std::vector<std::byte>
		std::vector<std::byte> compressedData(compressedString.size());
		std::transform(compressedString.begin(), compressedString.end(), compressedData.begin(),
			[](char c) { return static_cast<std::byte>(c); });

		// Create Buffer and write data
		StormByte::Buffer::FIFO buffer;
		buffer.Write(compressedData);
		return buffer;
		}
		catch (const CryptoPP::Exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}

	ExpectedCompressorBuffer DecompressHelper(std::span<const std::byte> compressedData) noexcept {
		try {
			std::string decompressedString;

			// Use Crypto++'s Gunzip for decompression
			CryptoPP::StringSource ss(
				reinterpret_cast<const uint8_t*>(compressedData.data()), compressedData.size_bytes(), true,
				new CryptoPP::Gunzip(new CryptoPP::StringSink(decompressedString)));

		// Convert the decompressed string to std::vector<std::byte>
		std::vector<std::byte> decompressedData(decompressedString.size());
		std::transform(decompressedString.begin(), decompressedString.end(), decompressedData.begin(),
			[](char c) { return static_cast<std::byte>(c); });

		// Create Buffer and write data
		StormByte::Buffer::FIFO buffer;
		buffer.Write(decompressedData);
		return buffer;
		}
		catch (const CryptoPP::Exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}
}

// Public Compress Methods
ExpectedCompressorBuffer Gzip::Compress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return CompressHelper(dataSpan);
}

ExpectedCompressorBuffer Gzip::Compress(const StormByte::Buffer::FIFO& input) noexcept {
	// Extract all data from FIFO to a span
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return CompressHelper(dataSpan);
}

StormByte::Buffer::Consumer Gzip::Compress(Buffer::Consumer consumer) noexcept {
	// Create a producer buffer to store the compressed data
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	// Launch a detached thread to handle compression
	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096; // Define the chunk size for reading from the consumer
			std::string compressedString;

			while (!consumer.IsClosed() || !consumer.Empty()) {
				// Check how many bytes are available in the consumer
				size_t availableBytes = consumer.AvailableBytes();

				if (availableBytes == 0) {
					if (consumer.IsClosed()) {
						break; // No more data will arrive
					}
					// Wait for more data to become available
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				// Read the available bytes (up to chunkSize)
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					producer->Close();
					return;
				}

				const auto& inputData = readResult.value();
				if (inputData.empty()) {
					continue;
				}

				// Use Crypto++'s Gzip for compression
				CryptoPP::StringSource ss(
					reinterpret_cast<const uint8_t*>(inputData.data()), inputData.size(), true,
					new CryptoPP::Gzip(new CryptoPP::StringSink(compressedString), CryptoPP::Gzip::MAX_DEFLATE_LEVEL));

				// Write the compressed data to the producer
				std::vector<std::byte> byteData(compressedString.size());
				std::transform(compressedString.begin(), compressedString.end(), byteData.begin(),
					[](char c) { return static_cast<std::byte>(c); });
				producer->Write(byteData);
				compressedString.clear();
			}
			producer->Close(); // Mark compression complete
		} catch (...) {
			producer->Close();
		}
	}).detach();

	// Return a consumer buffer for the producer
	return producer->Consumer();
}

// Public Decompress Methods
ExpectedCompressorBuffer Gzip::Decompress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecompressHelper(dataSpan);
}

ExpectedCompressorBuffer Gzip::Decompress(const StormByte::Buffer::FIFO& input) noexcept {
	// Extract all data from FIFO to a span
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return DecompressHelper(dataSpan);
}

StormByte::Buffer::Consumer Gzip::Decompress(Buffer::Consumer consumer) noexcept {
	// Create a producer buffer to store the decompressed data
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	// Launch a detached thread to handle decompression
	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096; // Define the chunk size for reading from the consumer
			std::string decompressedString;

			while (!consumer.IsClosed() || !consumer.Empty()) {
				// Check how many bytes are available in the consumer
				size_t availableBytes = consumer.AvailableBytes();

				if (availableBytes == 0) {
					if (consumer.IsClosed()) {
						break; // No more data will arrive
					}
					// Wait for more data to become available
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				// Read the available bytes (up to chunkSize)
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				auto readResult = consumer.Read(bytesToRead);
				if (!readResult.has_value()) {
					producer->Close();
					return;
				}

				const auto& compressedData = readResult.value();
				if (compressedData.empty()) {
					continue;
				}

				// Use Crypto++'s Gunzip for decompression
				CryptoPP::StringSource ss(
					reinterpret_cast<const uint8_t*>(compressedData.data()), compressedData.size(), true,
					new CryptoPP::Gunzip(new CryptoPP::StringSink(decompressedString)));

				// Write the decompressed data to the producer
				std::vector<std::byte> byteData(decompressedString.size());
				std::transform(decompressedString.begin(), decompressedString.end(), byteData.begin(),
					[](char c) { return static_cast<std::byte>(c); });
				producer->Write(byteData);
				decompressedString.clear();
			}
			producer->Close(); // Mark decompression complete
		} catch (...) {
			producer->Close();
		}
	}).detach();

	// Return a consumer buffer for the producer
	return producer->Consumer();
}
