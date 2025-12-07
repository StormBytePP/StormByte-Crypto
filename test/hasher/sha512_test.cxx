#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher/sha512.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestSHA512HashCorrectness() {
	const std::string fn_name = "TestSHA512HashCorrectness";
	const std::string input_data = "HashThisString";

	// Correct expected SHA-512 hash value (uppercase, split into two lines for readability)
	const std::string expected_hash = 
		"6D69A62B60C16398A2482B03FB56FB041E5014E3D8E1480833EB8427C3F45910"
		"B5B1ED812EC8C04087C92F47B50016C1495F358DD34E98723795E6E852B92875";

	Hasher::SHA512 sha512;

	// Compute hash for the input string
	FIFO hash_fifo;
	auto ok = sha512.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), hash_fifo);
	ASSERT_TRUE(fn_name, ok);
	std::string actual_hash = DeserializeString(hash_fifo.Data());

	// Validate the hash matches the expected value
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash);

	RETURN_TEST(fn_name, 0);
}

int TestSHA512CollisionResistance() {
	const std::string fn_name = "TestSHA512CollisionResistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!"; // Slightly different input

	Hasher::SHA512 sha512;

	// Compute hash for input_data_1
	FIFO hash_fifo_1;
	auto ok_1 = sha512.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_1.data()), input_data_1.size()), hash_fifo_1);
	ASSERT_TRUE(fn_name, ok_1);
	std::string hash_1 = DeserializeString(hash_fifo_1.Data());

	// Compute hash for input_data_2
	FIFO hash_fifo_2;
	auto ok_2 = sha512.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_2.data()), input_data_2.size()), hash_fifo_2);
	ASSERT_TRUE(fn_name, ok_2);
	std::string hash_2 = DeserializeString(hash_fifo_2.Data());

	// Ensure the hashes are different
	ASSERT_NOT_EQUAL(fn_name, hash_1, hash_2);

	RETURN_TEST(fn_name, 0);
}

int TestSHA512ProducesDifferentContent() {
	const std::string fn_name = "TestSHA512ProducesDifferentContent";
	const std::string original_data = "Data to hash";

	Hasher::SHA512 sha512;

	// Generate the hash
	FIFO hash_fifo;
	auto ok = sha512.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), hash_fifo);
	ASSERT_TRUE(fn_name, ok);
	std::string hashed_data = DeserializeString(hash_fifo.Data());

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

	Hasher::SHA512 sha512;

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Hash the data asynchronously
	auto hash_consumer = sha512.Hash(consumer);
	ASSERT_TRUE(fn_name, hash_consumer.IsWritable() || !hash_consumer.Empty());

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