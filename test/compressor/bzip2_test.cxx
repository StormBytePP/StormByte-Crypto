#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestBZip2CompressionDecompressionIntegrity() {
	const std::string fn_name = "TestBZip2CompressionDecompressionIntegrity";
	const std::string input_data = "OriginalDataForIntegrityCheck";

	Compressor::Bzip2 bzip2;

	// Compress the input string
	FIFO compressed_data;
	auto compress_result = bzip2.Compress(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), compressed_data);
	ASSERT_TRUE(fn_name, compress_result);
	ASSERT_FALSE(fn_name, compressed_data.Empty());

	// Decompress the compressed data
	FIFO decompressed_data;
	auto decompress_result = bzip2.Decompress(compressed_data, decompressed_data);
	ASSERT_TRUE(fn_name, decompress_result);
	ASSERT_FALSE(fn_name, decompressed_data.Empty());
	std::string decompressed_str = StormByte::String::FromByteVector(decompressed_data.Data());

	// Ensure the decompressed data matches the original input data
	ASSERT_EQUAL(fn_name, decompressed_str, input_data);

	RETURN_TEST(fn_name, 0);
}

int TestBzip2CompressionProducesDifferentContent() {
	const std::string fn_name = "TestBzip2CompressionProducesDifferentContent";
	const std::string original_data = "Compress this data";

	Compressor::Bzip2 bzip2;

	// Compress the data
	FIFO compressed_data;
	auto compress_result = bzip2.Compress(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), compressed_data);
	ASSERT_TRUE(fn_name, compress_result);
	ASSERT_FALSE(fn_name, compressed_data.Empty());

	auto compressed_string = StormByte::String::FromByteVector(compressed_data.Data());
	ASSERT_FALSE(fn_name, compressed_string.empty());

	// Verify compressed content is different from original
	ASSERT_NOT_EQUAL(fn_name, compressed_string, original_data);

	RETURN_TEST(fn_name, 0);
}

int TestBZip2DecompressCorruptedData() {
	const std::string fn_name = "TestBZip2DecompressCorruptedData";

	// Original valid data
	const std::string original_data = "This is some valid data to compress and corrupt.";

	Compressor::Bzip2 bzip2;

	// Compress the valid data
	FIFO compressed_data;
	auto compress_result = bzip2.Compress(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), compressed_data);
	ASSERT_TRUE(fn_name, compress_result);
	ASSERT_FALSE(fn_name, compressed_data.Empty());

	auto compressed_string = StormByte::String::FromByteVector(compressed_data.Data());
	ASSERT_FALSE(fn_name, compressed_string.empty());

	// Corrupt the compressed data
	// Bzip2 format has header bytes, corrupt multiple bytes to ensure detection
	std::string corrupted_string = compressed_string;
	if (corrupted_string.size() > 10) {
		// Corrupt multiple bytes in the compressed data for reliable failure
		corrupted_string[4] ^= 0xFF;  // Corrupt header/control byte
		corrupted_string[corrupted_string.size() / 2] ^= 0xFF;  // Corrupt middle
		corrupted_string[corrupted_string.size() - 3] ^= 0xFF;  // Corrupt near end
	} else if (!corrupted_string.empty()) {
		corrupted_string[0] ^= 0xFF;
	}

	// Attempt to decompress the corrupted data
	FIFO bad_decompress;
	auto decompress_result = bzip2.Decompress(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), bad_decompress);
	// Bzip2 should either fail to decompress OR produce different output
	if (decompress_result) {
		// If it decompressed, verify the output is corrupted (different from original)
		ASSERT_NOT_EQUAL(fn_name, StormByte::String::FromByteVector(bad_decompress.Data()), original_data);
	}
	// Either way, the test passes if we get here

	RETURN_TEST(fn_name, 0);
}

int TestBZip2CompressDecompressUsingConsumerProducer() {
	const std::string fn_name = "TestBZip2CompressDecompressUsingConsumerProducer";
	const std::string input_data = "This is some data to compress using the Consumer/Producer model.";
	
	Compressor::Bzip2 bzip2;

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Compress the data asynchronously
	auto compressed_consumer = bzip2.Compress(consumer);
	ASSERT_TRUE(fn_name, compressed_consumer.IsWritable() || !compressed_consumer.Empty());

	// Decompress the data asynchronously
	auto decompressed_consumer = bzip2.Decompress(compressed_consumer);
	ASSERT_TRUE(fn_name, decompressed_consumer.IsWritable() || !decompressed_consumer.Empty());
	// Read the decompressed data from the decompressed_consumer
	StormByte::Buffer::FIFO decompressed_data = ReadAllFromConsumer(decompressed_consumer);
	ASSERT_FALSE(fn_name, decompressed_data.Empty()); // Ensure compressed data is not empty

	std::string deserialized_string = DeserializeString(decompressed_data);
	ASSERT_EQUAL(fn_name, input_data, deserialized_string);

	RETURN_TEST(fn_name, 0);
}

int TestBzip2StreamingDecompress() {
	const std::string fn_name = "TestBzip2StreamingDecompress";
	std::string big(128 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));

	Compressor::Bzip2 bzip2;
	FIFO compressedFifo;
	auto ok = bzip2.Compress(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(big.data()), big.size()),
		compressedFifo);
	ASSERT_TRUE(fn_name, ok);
	ASSERT_FALSE(fn_name, compressedFifo.Empty());

	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const auto& raw = compressedFifo.Data();
	const size_t chunk = 4096;
	for (size_t off = 0; off < raw.size(); off += chunk) {
		size_t n = std::min(chunk, raw.size() - off);
		std::vector<std::byte> bytes(raw.begin() + static_cast<std::ptrdiff_t>(off),
									raw.begin() + static_cast<std::ptrdiff_t>(off + n));
		(void)producer.Write(bytes);
	}
	producer.Close();

	auto decompressedConsumer = bzip2.Decompress(consumerIn);
	auto decompressedFifo = ReadAllFromConsumer(decompressedConsumer);
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressedFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int TestBzip2StreamingRoundTrip() {
	const std::string fn_name = "TestBzip2StreamingRoundTrip";
	std::string big(64 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('a' + (i % 26));

	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const size_t chunk = 2048;
	for (size_t off = 0; off < big.size(); off += chunk) {
		size_t n = std::min(chunk, big.size() - off);
		std::vector<std::byte> bytes(n);
		std::transform(big.begin() + static_cast<std::ptrdiff_t>(off),
					big.begin() + static_cast<std::ptrdiff_t>(off + n),
					bytes.begin(),
					[](char c) { return static_cast<std::byte>(c); });
		(void)producer.Write(bytes);
	}
	producer.Close();

	Compressor::Bzip2 bzip2;
	auto compressedConsumer = bzip2.Compress(consumerIn);
	auto decompressedConsumer = bzip2.Decompress(compressedConsumer);
	auto outFifo = ReadAllFromConsumer(decompressedConsumer);
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(outFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int TestBzip2EmptyInput() {
	const std::string fn_name = "TestBzip2EmptyInput";
	Compressor::Bzip2 bzip2;

	FIFO compressed;
	auto c = bzip2.Compress(std::span<const std::byte>(), compressed);
	ASSERT_TRUE(fn_name, c);
	ASSERT_TRUE(fn_name, compressed.Empty());

	// Use span path: empty input is defined as success with empty output
	FIFO decompressed;
	auto d = bzip2.Decompress(std::span<const std::byte>(), decompressed);
	ASSERT_TRUE(fn_name, d);
	ASSERT_TRUE(fn_name, decompressed.Empty());
	RETURN_TEST(fn_name, 0);
}

int TestBzip2CompressLevelBounds() {
	const std::string fn_name = "TestBzip2CompressLevelBounds";
	const std::string input = "level-bounds-test-payload";

	for (unsigned short level : {1, 5, 9}) {
		Compressor::Bzip2 bzip2(level);
		FIFO compressed;
		ASSERT_TRUE(fn_name,
			bzip2.Compress(
				std::span<const std::byte>(reinterpret_cast<const std::byte*>(input.data()), input.size()),
				compressed));
		FIFO decompressed;
		ASSERT_TRUE(fn_name, bzip2.Decompress(compressed, decompressed));
		ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressed.Data()), input);
	}
	RETURN_TEST(fn_name, 0);
}

int TestBzip2BufferPath() {
	const std::string fn_name = "TestBzip2BufferPath";
	std::string src(1024, 'B');
	FIFO input;
	std::vector<std::byte> bytes(src.size());
	std::transform(src.begin(), src.end(), bytes.begin(),
				[](char c) { return static_cast<std::byte>(c); });
	input.Write(bytes);

	Compressor::Bzip2 bzip2;
	FIFO compressed;
	ASSERT_TRUE(fn_name, bzip2.Compress(input, compressed));

	FIFO decompressed;
	ASSERT_TRUE(fn_name, bzip2.Decompress(compressed, decompressed));
	ASSERT_EQUAL(fn_name, StormByte::String::FromByteVector(decompressed.Data()), src);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestBZip2CompressionDecompressionIntegrity();
	result += TestBzip2CompressionProducesDifferentContent();
	result += TestBZip2DecompressCorruptedData();
	result += TestBZip2CompressDecompressUsingConsumerProducer();
	result += TestBzip2StreamingDecompress();
	result += TestBzip2StreamingRoundTrip();
	result += TestBzip2EmptyInput();
	result += TestBzip2CompressLevelBounds();
	result += TestBzip2BufferPath();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
