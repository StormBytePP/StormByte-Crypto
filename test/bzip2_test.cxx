#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/compressor.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestBZip2CompressionDecompressionIntegrity() {
	const std::string fn_name = "TestBZip2CompressionDecompressionIntegrity";
	const std::string input_data = "OriginalDataForIntegrityCheck";

	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Compress the input string
	auto compress_result = bzip2.Compress(input_data);
	ASSERT_TRUE(fn_name, compress_result.has_value());
	auto compressed_data = compress_result.value();

	// Decompress the compressed data
	auto decompress_result = bzip2.Decompress(compressed_data);
	ASSERT_TRUE(fn_name, decompress_result.has_value());
	std::string decompressed_str = decompress_result.value();

	// Ensure the decompressed data matches the original input data
	ASSERT_EQUAL(fn_name, input_data, decompressed_str);

	RETURN_TEST(fn_name, 0);
}

int TestBzip2CompressionProducesDifferentContent() {
	const std::string fn_name = "TestBzip2CompressionProducesDifferentContent";
	const std::string original_data = "Compress this data";

	Compressor bzip2(Algorithm::Compress::Bzip2);

	// Compress the data
	auto compress_result = bzip2.Compress(original_data);
	ASSERT_TRUE(fn_name, compress_result.has_value());

	auto compressed_string = compress_result.value();
	ASSERT_FALSE(fn_name, compressed_string.empty());

	// Verify compressed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, compressed_string);

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

	auto compressed_string = compress_result.value();
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
	auto decompress_result = bzip2.Decompress(corrupted_string);
	// Bzip2 should either fail to decompress OR produce different output
	if (decompress_result.has_value()) {
		// If it decompressed, verify the output is corrupted (different from original)
		ASSERT_NOT_EQUAL(fn_name, decompress_result.value(), original_data);
	}
	// Either way, the test passes if we get here

	RETURN_TEST(fn_name, 0);
}

int TestBZip2CompressDecompressUsingConsumerProducer() {
	const std::string fn_name = "TestBZip2CompressDecompressUsingConsumerProducer";
	const std::string input_data = "This is some data to compress using the Consumer/Producer model.";
	
	Compressor bzip2(Algorithm::Compress::Bzip2);

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

int main() {
	int result = 0;

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