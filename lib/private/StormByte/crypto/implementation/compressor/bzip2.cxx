#include <StormByte/crypto/implementation/compressor/bzip2.hxx>

#include <algorithm>
#include <bzlib.h>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <span>
#include <thread>
#include <vector>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
using namespace StormByte::Crypto::Implementation::Compressor;

namespace {
	ExpectedCompressorBuffer CompressHelper(std::span<const std::byte> inputData, int blockSize = 9) noexcept {
		try {
			unsigned int compressedSize = static_cast<unsigned int>(std::ceil(inputData.size_bytes() * 1.01 + 600));
			std::vector<uint8_t> compressedData(compressedSize);

		if (BZ2_bzBuffToBuffCompress(reinterpret_cast<char*>(compressedData.data()), &compressedSize,
			const_cast<char*>(reinterpret_cast<const char*>(inputData.data())),
			static_cast<unsigned int>(inputData.size_bytes()), blockSize, 0, 30) != BZ_OK) {
				return Unexpected(CompressorException("BZip2 compression failed"));
			}

		compressedData.resize(compressedSize);
		
		FIFO buffer;
		(void)buffer.Write(std::move(compressedData));
		return buffer;
		}
		catch (const std::exception& e) {
			return Unexpected(CompressorException(e.what()));
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
		}			if (result != BZ_OK) {
				return Unexpected(CompressorException("BZip2 decompression failed"));
			}

		// Resize the buffer to the actual decompressed size
		decompressedData.resize(decompressedSize);
		
		// Convert to std::byte vector and create FIFO
		std::vector<std::byte> byteData(decompressedSize);
		std::transform(decompressedData.begin(), decompressedData.end(), byteData.begin(),
			[](uint8_t b) { return static_cast<std::byte>(b); });
		
		FIFO buffer;
		(void)buffer.Write(byteData);
		return buffer;
		} catch (const std::exception& e) {
			return Unexpected(CompressorException(e.what()));
		}
	}
}

// Public Compress Methods
ExpectedCompressorBuffer BZip2::Compress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return CompressHelper(dataSpan);
}

ExpectedCompressorBuffer BZip2::Compress(const FIFO& input) noexcept {
	// Extract all data from FIFO to a span
	DataType data;
	auto read_ok = input.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(CompressorException("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return CompressHelper(dataSpan);
}

Consumer BZip2::Compress(Consumer consumer) noexcept {
	// Create a producer buffer to store the compressed data
	Producer producer;

	// Launch a detached thread to handle compression
	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			std::vector<uint8_t> compressedBuffer(chunkSize * 2);

			// Initialize bzip2 stream
			bz_stream stream;
			std::memset(&stream, 0, sizeof(stream));
			if (BZ2_bzCompressInit(&stream, 9, 0, 30) != BZ_OK) {
				producer.Close();
				return;
			}

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();

				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto read_ok = consumer.Extract(bytesToRead, data);
				if (!read_ok.has_value()) {
					BZ2_bzCompressEnd(&stream);
					producer.SetError();
					return;
				}

				// Feed data to compressor
				stream.next_in = const_cast<char*>(reinterpret_cast<const char*>(data.data()));
				stream.avail_in = static_cast<unsigned int>(data.size());
				do {
					stream.next_out = reinterpret_cast<char*>(compressedBuffer.data());
					stream.avail_out = static_cast<unsigned int>(compressedBuffer.size());

					int result = BZ2_bzCompress(&stream, BZ_RUN);
					if (result < 0) {
						BZ2_bzCompressEnd(&stream);
						producer.SetError();
						return;
					}

					size_t produced = compressedBuffer.size() - stream.avail_out;
					if (produced > 0) {
						///< @todo Optimize to avoid double copy
						std::vector<std::byte> byteData(produced);
						std::transform(compressedBuffer.begin(), compressedBuffer.begin() + produced, byteData.begin(),
							[](uint8_t b) { return static_cast<std::byte>(b); });
						(void)producer.Write(std::move(byteData));
					}
				} while (stream.avail_in > 0);
			}

			// Finalize compression
			stream.next_in = nullptr;
			stream.avail_in = 0;
			int result;
			do {
				stream.next_out = reinterpret_cast<char*>(compressedBuffer.data());
				stream.avail_out = static_cast<unsigned int>(compressedBuffer.size());
				result = BZ2_bzCompress(&stream, BZ_FINISH);
				size_t produced = compressedBuffer.size() - stream.avail_out;
				if (produced > 0) {
					///< @todo Optimize to avoid double copy
					std::vector<std::byte> byteData(produced);
					std::transform(compressedBuffer.begin(), compressedBuffer.begin() + produced, byteData.begin(),
						[](uint8_t b) { return static_cast<std::byte>(b); });
					(void)producer.Write(std::move(byteData));
				}
			} while (result != BZ_STREAM_END);

			BZ2_bzCompressEnd(&stream);
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	// Return a consumer buffer for the producer
	return producer.Consumer();
}

// Public Decompress Methods
ExpectedCompressorBuffer BZip2::Decompress(const std::string& input) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecompressHelper(dataSpan);
}

ExpectedCompressorBuffer BZip2::Decompress(const FIFO& input) noexcept {
	// Extract all data from FIFO to a span
	DataType data;
	auto read_ok = input.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(CompressorException("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return DecompressHelper(dataSpan);
}

Consumer BZip2::Decompress(Consumer consumer) noexcept {
	// Create a producer buffer to store the decompressed data
	Producer producer;

	// Launch a detached thread to handle decompression
	std::thread([consumer, producer]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			std::vector<uint8_t> decompressedBuffer(chunkSize * 2);

			// Initialize bzip2 stream
			bz_stream stream;
			std::memset(&stream, 0, sizeof(stream));
			if (BZ2_bzDecompressInit(&stream, 0, 0) != BZ_OK) {
				producer.SetError();
				return;
			}

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();

				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto read_ok = consumer.Read(bytesToRead, data);
				if (!read_ok.has_value()) {
					BZ2_bzDecompressEnd(&stream);
					producer.SetError();
					return;
				}

				// Feed data to decompressor
				stream.next_in = const_cast<char*>(reinterpret_cast<const char*>(data.data()));
				stream.avail_in = static_cast<unsigned int>(data.size());
				do {
					stream.next_out = reinterpret_cast<char*>(decompressedBuffer.data());
					stream.avail_out = static_cast<unsigned int>(decompressedBuffer.size());

					int result = BZ2_bzDecompress(&stream);
					if (result < 0) {
						BZ2_bzDecompressEnd(&stream);
						producer.SetError();
						return;
					}

					size_t produced = decompressedBuffer.size() - stream.avail_out;
					if (produced > 0) {
						///< @todo Optimize to avoid double copy
						std::vector<std::byte> byteData(produced);
						std::transform(decompressedBuffer.begin(), decompressedBuffer.begin() + produced, byteData.begin(),
							[](uint8_t b) { return static_cast<std::byte>(b); });
						(void)producer.Write(std::move(byteData));
					}

					if (result == BZ_STREAM_END) break;
				} while (stream.avail_in > 0);
			}

			BZ2_bzDecompressEnd(&stream);
			producer.Close();
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	// Return a consumer buffer for the producer
	return producer.Consumer();
}
