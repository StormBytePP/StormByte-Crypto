#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestBlake2bHashCorrectness() {
	const std::string fn_name = "TestBlake2bHashCorrectness";
	const std::string input_data = "HashThisString";

	// Correct expected Blake2b hash value (uppercase, split into two lines for readability)
	const std::string expected_hash = 
		"66CCD3A78741E16F894F2FB20045A8678D12B73D9CBA95D3473B1029781D6587"
		"648E839960BDA14F0FF075C0EC9E7ED1AA13197BEED8B027EEA32800453CC7F8";
	
	Hasher blake2b(Algorithm::Hash::Blake2b);

	// Compute hash for the input string
	auto hash_result = blake2b.Hash(input_data);
	ASSERT_TRUE(fn_name, hash_result.has_value());
	std::string actual_hash = hash_result.value();

	// Validate the hash matches the expected value
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash);

	RETURN_TEST(fn_name, 0);
}

int TestBlake2bCollisionResistance() {
	const std::string fn_name = "TestBlake2bCollisionResistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!"; // Slightly different input

	Hasher blake2b(Algorithm::Hash::Blake2b);

	// Compute hash for input_data_1
	auto hash_result_1 = blake2b.Hash(input_data_1);
	ASSERT_TRUE(fn_name, hash_result_1.has_value());
	std::string hash_1 = hash_result_1.value();

	// Compute hash for input_data_2
	auto hash_result_2 = blake2b.Hash(input_data_2);
	ASSERT_TRUE(fn_name, hash_result_2.has_value());
	std::string hash_2 = hash_result_2.value();

	// Ensure the hashes are different
	ASSERT_NOT_EQUAL(fn_name, hash_1, hash_2);

	RETURN_TEST(fn_name, 0);
}

int TestBlake2bProducesDifferentContent() {
	const std::string fn_name = "TestBlake2bProducesDifferentContent";
	const std::string original_data = "Data to hash";

	Hasher blake2b(Algorithm::Hash::Blake2b);

	// Generate the hash
	auto hash_result = blake2b.Hash(original_data);
	ASSERT_TRUE(fn_name, hash_result.has_value());
	std::string hashed_data = hash_result.value();

	// Verify hashed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, hashed_data);

	RETURN_TEST(fn_name, 0);
}

int TestBlake2bHashUsingConsumerProducer() {
	const std::string fn_name = "TestBlake2bHashUsingConsumerProducer";
	const std::string input_data = "HashThisString";

	// Expected Blake2b hash value (from TestBlake2bHashCorrectness)
	const std::string expected_hash = 
		"66CCD3A78741E16F894F2FB20045A8678D12B73D9CBA95D3473B1029781D6587"
		"648E839960BDA14F0FF075C0EC9E7ED1AA13197BEED8B027EEA32800453CC7F8";

	Hasher blake2b(Algorithm::Hash::Blake2b);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer << input_data;
	producer << StormByte::Buffer::Status::ReadOnly; // Mark the producer as EOF

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Hash the data asynchronously
	auto hash_consumer = blake2b.Hash(consumer);
	ASSERT_TRUE(fn_name, hash_consumer.IsReadable());

	// Read the hash result from the hash_consumer
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(fn_name, hash_result.Empty()); // Ensure hash result is not empty
	std::string hashed_data = DeserializeString(hash_result);
	ASSERT_EQUAL(fn_name, expected_hash, hashed_data);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestBlake2bHashCorrectness();
	result += TestBlake2bCollisionResistance();
	result += TestBlake2bProducesDifferentContent();
	result += TestBlake2bHashUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}