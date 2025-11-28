#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestSHA256HashCorrectness() {
	const std::string fn_name = "TestSHA256HashCorrectness";
	const std::string input_data = "HashThisString";

	// Expected SHA-256 hash value (use an external tool or verified source to precompute the correct hash)
	const std::string expected_hash = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";

	Hasher sha256(Algorithm::Hash::SHA256);

	// Compute hash for the input string
	auto hash_result = sha256.Hash(input_data);
	ASSERT_TRUE(fn_name, hash_result.has_value());
	std::string actual_hash = hash_result.value();

	// Validate the hash matches the expected value
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash);

	RETURN_TEST(fn_name, 0);
}

int TestSHA256CollisionResistance() {
	const std::string fn_name = "TestSHA256CollisionResistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!"; // Slightly different input

	Hasher sha256(Algorithm::Hash::SHA256);

	// Compute hash for input_data_1
	auto hash_result_1 = sha256.Hash(input_data_1);
	ASSERT_TRUE(fn_name, hash_result_1.has_value());
	std::string hash_1 = hash_result_1.value();

	// Compute hash for input_data_2
	auto hash_result_2 = sha256.Hash(input_data_2);
	ASSERT_TRUE(fn_name, hash_result_2.has_value());
	std::string hash_2 = hash_result_2.value();

	// Ensure the hashes are different
	ASSERT_NOT_EQUAL(fn_name, hash_1, hash_2);

	RETURN_TEST(fn_name, 0);
}

int TestSHA256ProducesDifferentContent() {
	const std::string fn_name = "TestSHA256ProducesDifferentContent";
	const std::string original_data = "Data to hash";

	Hasher sha256(Algorithm::Hash::SHA256);

	// Generate the hash
	auto hash_result = sha256.Hash(original_data);
	ASSERT_TRUE(fn_name, hash_result.has_value());
	std::string hashed_data = hash_result.value();

	// Verify hashed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, hashed_data);

	RETURN_TEST(fn_name, 0);
}

int TestSHA256HashUsingConsumerProducer() {
	const std::string fn_name = "TestSHA256HashUsingConsumerProducer";
	const std::string input_data = "HashThisString";

	// Expected SHA-256 hash value (from TestSHA256HashCorrectness)
	const std::string expected_hash = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";

	Hasher sha256(Algorithm::Hash::SHA256);

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

int main() {
	int result = 0;

	result += TestSHA256HashCorrectness();
	result += TestSHA256CollisionResistance();
	result += TestSHA256ProducesDifferentContent();
	result += TestSHA256HashUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
