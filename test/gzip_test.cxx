#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/compressor.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestGzipCompressionDecompressionIntegrity() {
	const std::string fn_name = "TestGzipCompressionDecompressionIntegrity";
	const std::string input_data = "OriginalDataForIntegrityCheck";

	Compressor gzip(Algorithm::Compress::Gzip);

	// Compress the input string
	auto compress_result = gzip.Compress(input_data);
	ASSERT_TRUE(fn_name, compress_result.has_value());
	auto compressed_data = compress_result.value();

	// Decompress the compressed data
	auto decompress_result = gzip.Decompress(compressed_data);
	ASSERT_TRUE(fn_name, decompress_result.has_value());
	std::string decompressed_str = decompress_result.value();

	// Ensure the decompressed data matches the original input data
	ASSERT_EQUAL(fn_name, input_data, decompressed_str);

	RETURN_TEST(fn_name, 0);
}

int TestGzipCompressionProducesDifferentContent() {
	const std::string fn_name = "TestGzipCompressionProducesDifferentContent";
	const std::string original_data = "Compress this data";

	Compressor gzip(Algorithm::Compress::Gzip);

	// Compress the data
	auto compress_result = gzip.Compress(original_data);
	ASSERT_TRUE(fn_name, compress_result.has_value());

	auto compressed_string = compress_result.value();
	ASSERT_FALSE(fn_name, compressed_string.empty());

	// Verify compressed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, compressed_string);

	RETURN_TEST(fn_name, 0);
}

int TestGzipCompressDecompressUsingConsumerProducer() {
	const std::string fn_name = "TestGzipCompressDecompressUsingConsumerProducer";
	const std::string input_data = "This is some data to compress using the Consumer/Producer model.";

	Compressor gzip(Algorithm::Compress::Gzip);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Compress the data asynchronously
	auto compressed_consumer = gzip.Compress(consumer);
	ASSERT_TRUE(fn_name, compressed_consumer.IsWritable() || !compressed_consumer.Empty());

	// Decompress the data asynchronously
	auto decompressed_consumer = gzip.Decompress(compressed_consumer);
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

	result += TestGzipCompressionDecompressionIntegrity();
	result += TestGzipCompressionProducesDifferentContent();
	result += TestGzipCompressDecompressUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
