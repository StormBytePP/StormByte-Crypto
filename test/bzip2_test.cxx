#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/compressor.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestBZip2CompressConsistencyAcrossFormats() {
	const std::string fn_name = "TestBZip2CompressConsistencyAcrossFormats";
	const std::string input_data = "DataToCompress";

	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Compress a string
	auto compress_string_result = bzip2.Compress(input_data);
	ASSERT_TRUE(fn_name, compress_string_result.has_value());
	auto compressed_from_string_future = std::move(compress_string_result.value());
	StormByte::Buffer::Simple compressed_from_string = compressed_from_string_future;

	// Compress a Buffer
	StormByte::Buffer::Simple input_buffer;
	input_buffer << input_data;
	auto compress_buffer_result = bzip2.Compress(input_buffer);
	ASSERT_TRUE(fn_name, compress_buffer_result.has_value());
	auto compressed_from_buffer_future = std::move(compress_buffer_result.value());
	StormByte::Buffer::Simple compressed_from_buffer = compressed_from_buffer_future;

	// Compress a Simple buffer
	auto compress_future_result = bzip2.Compress(input_buffer);
	ASSERT_TRUE(fn_name, compress_future_result.has_value());
	auto compressed_from_future_future = std::move(compress_future_result.value());
	StormByte::Buffer::Simple compressed_from_future = compressed_from_future_future;

	// Validate all compressed outputs are identical in size
	ASSERT_EQUAL(fn_name, compressed_from_string.Size(), compressed_from_buffer.Size());
	ASSERT_EQUAL(fn_name, compressed_from_buffer.Size(), compressed_from_future.Size());

	RETURN_TEST(fn_name, 0);
}

int TestBZip2DecompressConsistencyAcrossFormats() {
	const std::string fn_name = "TestBZip2DecompressConsistencyAcrossFormats";
	const std::string input_data = "DataToCompressAndDecompress";

	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Compress and then decompress a string
	auto compress_string_result = bzip2.Compress(input_data);
	ASSERT_TRUE(fn_name, compress_string_result.has_value());
	auto compressed_string_future = std::move(compress_string_result.value());
	StormByte::Buffer::Simple compressed_string = compressed_string_future;
	auto decompress_string_result = bzip2.Decompress(compressed_string);
	ASSERT_TRUE(fn_name, decompress_string_result.has_value());
	auto decompressed_from_string_future = std::move(decompress_string_result.value());
	StormByte::Buffer::Simple decompressed_from_string = decompressed_from_string_future;
	std::string decompressed_string_result(reinterpret_cast<const char*>(decompressed_from_string.Data().data()),
										decompressed_from_string.Size());

	// Compress and then decompress a Buffer
	StormByte::Buffer::Simple input_buffer;
	input_buffer << input_data;
	auto compress_buffer_result = bzip2.Compress(input_buffer);
	ASSERT_TRUE(fn_name, compress_buffer_result.has_value());
	auto compressed_buffer_future = std::move(compress_buffer_result.value());
	StormByte::Buffer::Simple compressed_buffer = compressed_buffer_future;
	auto decompress_buffer_result = bzip2.Decompress(compressed_buffer);
	ASSERT_TRUE(fn_name, decompress_buffer_result.has_value());
	auto decompressed_from_buffer_future = std::move(decompress_buffer_result.value());
	StormByte::Buffer::Simple decompressed_from_buffer = decompressed_from_buffer_future;
	std::string decompressed_buffer_result(reinterpret_cast<const char*>(decompressed_from_buffer.Data().data()),
										decompressed_from_buffer.Size());

	// Ensure decompressed results match the original data
	ASSERT_EQUAL(fn_name, input_data, decompressed_string_result);
	ASSERT_EQUAL(fn_name, input_data, decompressed_buffer_result);

	RETURN_TEST(fn_name, 0);
}

int TestBZip2CompressionDecompressionIntegrity() {
	const std::string fn_name = "TestBZip2CompressionDecompressionIntegrity";
	const std::string input_data = "OriginalDataForIntegrityCheck";

	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Compress the input string
	auto compress_result = bzip2.Compress(input_data);
	ASSERT_TRUE(fn_name, compress_result.has_value());
	auto compressed_data_future = std::move(compress_result.value());
	StormByte::Buffer::Simple compressed_data = compressed_data_future;

	// Decompress the compressed data
	auto decompress_result = bzip2.Decompress(compressed_data);
	ASSERT_TRUE(fn_name, decompress_result.has_value());
	auto decompressed_data_future = std::move(decompress_result.value());
	StormByte::Buffer::Simple decompressed_data = decompressed_data_future;
	std::string decompressed_result(reinterpret_cast<const char*>(decompressed_data.Data().data()),
									decompressed_data.Size());

	// Ensure the decompressed data matches the original input data
	ASSERT_EQUAL(fn_name, input_data, decompressed_result);

	RETURN_TEST(fn_name, 0);
}

int TestBzip2CompressionProducesDifferentContent() {
	const std::string fn_name = "TestBzip2CompressionProducesDifferentContent";
	const std::string original_data = "Compress this data";

	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Compress the data
	auto compress_result = bzip2.Compress(original_data);
	ASSERT_TRUE(fn_name, compress_result.has_value());
	auto compressed_future = std::move(compress_result.value());
	StormByte::Buffer::Simple compressed_buffer = compressed_future;
	ASSERT_FALSE(fn_name, compressed_buffer.Empty());

	// Verify compressed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, std::string(reinterpret_cast<const char*>(compressed_buffer.Data().data()), compressed_buffer.Size()));

	RETURN_TEST(fn_name, 0);
}

int TestBZip2DecompressCorruptedData() {
	const std::string fn_name = "TestBZip2DecompressCorruptedData";

	// Original valid data
	const std::string original_data = "This is some valid data to compress and corrupt.";

	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Compress the valid data
	auto compress_result = bzip2.Compress(original_data);
	ASSERT_TRUE(fn_name, compress_result.has_value());
	auto compressed_future = std::move(compress_result.value());
	StormByte::Buffer::Simple compressed_buffer = compressed_future;
	ASSERT_FALSE(fn_name, compressed_buffer.Empty());

	// Flip a single bit in the compressed data to simulate corruption
	std::vector<std::byte> corrupted_data = compressed_buffer.Data();
	corrupted_data[0] ^= std::byte(0x01); // Flip the least significant bit of the first byte

	// Wrap the corrupted data in a StormByte::Buffer::Simple buffer
	StormByte::Buffer::Simple corrupted_buffer;
	corrupted_buffer << corrupted_data;

	// Attempt to decompress the corrupted data
	auto decompress_result = bzip2.Decompress(corrupted_buffer);
	ASSERT_FALSE(fn_name, decompress_result.has_value()); // Expect decompression to fail

	RETURN_TEST(fn_name, 0);
}

int TestBZip2CompressDecompressUsingConsumerProducer() {
	const std::string fn_name = "TestBZip2CompressDecompressUsingConsumerProducer";
	const std::string input_data = "This is some data to compress using the Consumer/Producer model.";
	
	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer << input_data;
	producer << StormByte::Buffer::Status::ReadOnly; // Mark the producer as EOF

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Compress the data asynchronously
	auto compressed_consumer = bzip2.Compress(consumer);
	ASSERT_TRUE(fn_name, compressed_consumer.IsReadable());

	// Decompress the data asynchronously
	auto decompressed_consumer = bzip2.Decompress(compressed_consumer);
	ASSERT_TRUE(fn_name, decompressed_consumer.IsReadable());

	// Read the decompressed data from the decompressed_consumer
	StormByte::Buffer::Simple decompressed_data = ReadAllFromConsumer(decompressed_consumer);
	ASSERT_FALSE(fn_name, decompressed_data.Empty()); // Ensure compressed data is not empty

	std::string deserialized_string = DeserializeString(decompressed_data);
	ASSERT_EQUAL(fn_name, input_data, deserialized_string);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestBZip2CompressConsistencyAcrossFormats();
	result += TestBZip2DecompressConsistencyAcrossFormats();
	result += TestBZip2CompressionDecompressionIntegrity();
	result += TestBzip2CompressionProducesDifferentContent();
	result += TestBZip2DecompressCorruptedData();
	result += TestBZip2CompressDecompressUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}