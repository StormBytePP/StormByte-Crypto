#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestSHA512HashCorrectness() {
	const std::string fn_name = "TestSHA512HashCorrectness";
	const std::string input_data = "HashThisString";

	// Correct expected SHA-512 hash value (uppercase, split into two lines for readability)
	const std::string expected_hash = 
		"6D69A62B60C16398A2482B03FB56FB041E5014E3D8E1480833EB8427C3F45910"
		"B5B1ED812EC8C04087C92F47B50016C1495F358DD34E98723795E6E852B92875";

	Hasher sha512(Algorithm::Hash::SHA512);

	// Compute hash for the input string
	auto hash_result = sha512.Hash(input_data);
	ASSERT_TRUE(fn_name, hash_result.has_value());
	std::string actual_hash = hash_result.value();

	// Validate the hash matches the expected value
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash);

	RETURN_TEST(fn_name, 0);
}

int TestSHA512CollisionResistance() {
	const std::string fn_name = "TestSHA512CollisionResistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!"; // Slightly different input

	Hasher sha512(Algorithm::Hash::SHA512);

	// Compute hash for input_data_1
	auto hash_result_1 = sha512.Hash(input_data_1);
	ASSERT_TRUE(fn_name, hash_result_1.has_value());
	std::string hash_1 = hash_result_1.value();

	// Compute hash for input_data_2
	auto hash_result_2 = sha512.Hash(input_data_2);
	ASSERT_TRUE(fn_name, hash_result_2.has_value());
	std::string hash_2 = hash_result_2.value();

	// Ensure the hashes are different
	ASSERT_NOT_EQUAL(fn_name, hash_1, hash_2);

	RETURN_TEST(fn_name, 0);
}

int TestSHA512ProducesDifferentContent() {
	const std::string fn_name = "TestSHA512ProducesDifferentContent";
	const std::string original_data = "Data to hash";

	Hasher sha512(Algorithm::Hash::SHA512);

	// Generate the hash
	auto hash_result = sha512.Hash(original_data);
	ASSERT_TRUE(fn_name, hash_result.has_value());
	std::string hashed_data = hash_result.value();

	// Verify hashed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, hashed_data);

	RETURN_TEST(fn_name, 0);
}

int TestSHA512HashUsingConsumerProducer() {
	const std::string fn_name = "TestSHA512HashUsingConsumerProducer";
	const std::string input_data = "HashThisString";

	// Expected SHA-512 hash value (from TestSHA512HashCorrectness)
	const std::string expected_hash = 
		"6D69A62B60C16398A2482B03FB56FB041E5014E3D8E1480833EB8427C3F45910"
		"B5B1ED812EC8C04087C92F47B50016C1495F358DD34E98723795E6E852B92875";

	Hasher sha512(Algorithm::Hash::SHA512);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Hash the data asynchronously
	auto hash_consumer = sha512.Hash(consumer);
	ASSERT_TRUE(fn_name, !hash_consumer.IsClosed() || !hash_consumer.Empty());

	// Read the hash result from the hash_consumer
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(fn_name, hash_result.Empty());
	std::string actual_hash = DeserializeString(hash_result);
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash); // Ensure hash result matches expected value

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestSHA512HashCorrectness();
	result += TestSHA512CollisionResistance();
	result += TestSHA512ProducesDifferentContent();
	result += TestSHA512HashUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}