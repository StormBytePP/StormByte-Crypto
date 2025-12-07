#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher/sha256.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestSHA256HashCorrectness() {
	const std::string fn_name = "TestSHA256HashCorrectness";
	const std::string input_data = "HashThisString";

	// Expected SHA-256 hash value (use an external tool or verified source to precompute the correct hash)
	const std::string expected_hash = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";

	Hasher::SHA256 sha256;

	// Compute hash for the input string
	FIFO hash;
	auto ok = sha256.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), hash);
	ASSERT_TRUE(fn_name, ok);
	std::string actual_hash = StormByte::String::FromByteVector(hash.Data());

	// Validate the hash matches the expected value
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash);

	RETURN_TEST(fn_name, 0);
}

int TestSHA256CollisionResistance() {
	const std::string fn_name = "TestSHA256CollisionResistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!"; // Slightly different input

	Hasher::SHA256 sha256;

	// Compute hash for input_data_1
	FIFO hash_1_fifo;
	auto ok_1 = sha256.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_1.data()), input_data_1.size()), hash_1_fifo);
	ASSERT_TRUE(fn_name, ok_1);
	std::string hash_1 = StormByte::String::FromByteVector(hash_1_fifo.Data());

	// Compute hash for input_data_2
	FIFO hash_2_fifo;
	auto ok_2 = sha256.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_2.data()), input_data_2.size()), hash_2_fifo);
	ASSERT_TRUE(fn_name, ok_2);
	std::string hash_2 = StormByte::String::FromByteVector(hash_2_fifo.Data());

	// Ensure the hashes are different
	ASSERT_NOT_EQUAL(fn_name, hash_1, hash_2);

	RETURN_TEST(fn_name, 0);
}

int TestSHA256ProducesDifferentContent() {
	const std::string fn_name = "TestSHA256ProducesDifferentContent";
	const std::string original_data = "Data to hash";
	const std::string different_data = "Data to hosh";

	Hasher::SHA256 sha256;

	// Generate the hash
	FIFO hash_fifo;
	auto ok = sha256.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), hash_fifo);
	ASSERT_TRUE(fn_name, ok);
	std::string hashed_data = StormByte::String::FromByteVector(hash_fifo.Data());
	FIFO hash_fifo_2;
	auto ok_2 = sha256.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(different_data.data()), different_data.size()), hash_fifo_2);
	ASSERT_TRUE(fn_name, ok_2);
	std::string hashed_data_2 = StormByte::String::FromByteVector(hash_fifo_2.Data());

	// Verify hashed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, hashed_data);

	RETURN_TEST(fn_name, 0);
}

int TestSHA256HashUsingConsumerProducer() {
	const std::string fn_name = "TestSHA256HashUsingConsumerProducer";
	const std::string input_data = "HashThisString";

	// Expected SHA-256 hash value (from TestSHA256HashCorrectness)
	const std::string expected_hash = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";

	Hasher::SHA256 sha256;

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Hash the data asynchronously
	auto hash_consumer = sha256.Hash(consumer);
	ASSERT_TRUE(fn_name, hash_consumer.IsWritable() || !hash_consumer.Empty());

	// Read the hash result from the hash_consumer
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(fn_name, hash_result.Empty()); // Ensure hash result is not empty
	std::string actual_hash = DeserializeString(hash_result);
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash); // Ensure hash matches expected value

	RETURN_TEST(fn_name, 0);
}

int test_stream_and_block_equality() {
	const std::string fn_name = "test_stream_and_block_equality";
	const std::string input_data = "Data to hash for stream and block equality test";

	Hasher::SHA256 sha256;

	// Hash using block method
	FIFO block_hash_fifo;
	auto ok = sha256.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), block_hash_fifo);
	ASSERT_TRUE(fn_name, ok);
	std::string block_hash = StormByte::String::FromByteVector(block_hash_fifo.Data());

	// Hash using stream method
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	auto stream_hash_consumer = sha256.Hash(consumer);
	ASSERT_TRUE(fn_name, stream_hash_consumer.IsWritable() || !stream_hash_consumer.Empty());
	auto stream_hash_result = ReadAllFromConsumer(stream_hash_consumer);
	ASSERT_FALSE(fn_name, stream_hash_result.Empty());
	std::string stream_hash = DeserializeString(stream_hash_result);

	// Compare both hashes
	ASSERT_EQUAL(fn_name, block_hash, stream_hash);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestSHA256HashCorrectness();
	result += TestSHA256CollisionResistance();
	result += TestSHA256ProducesDifferentContent();
	result += TestSHA256HashUsingConsumerProducer();
	result += test_stream_and_block_equality();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
