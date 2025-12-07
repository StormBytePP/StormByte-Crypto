#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher/blake2b.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestBlake2bHashCorrectness() {
	const std::string fn_name = "TestBlake2bHashCorrectness";
	const std::string input_data = "HashThisString";

	// Correct expected Blake2b hash value (uppercase, split into two lines for readability)
	const std::string expected_hash = 
		"66CCD3A78741E16F894F2FB20045A8678D12B73D9CBA95D3473B1029781D6587"
		"648E839960BDA14F0FF075C0EC9E7ED1AA13197BEED8B027EEA32800453CC7F8";
	
	Hasher::Blake2b blake2b;

	// Compute hash for the input string
	FIFO hash;
	auto hash_result = blake2b.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), hash);
	ASSERT_TRUE(fn_name, hash_result);
	std::string actual_hash = StormByte::String::FromByteVector(hash.Data());

	// Validate the hash matches the expected value
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash);

	RETURN_TEST(fn_name, 0);
}

int TestBlake2bCollisionResistance() {
	const std::string fn_name = "TestBlake2bCollisionResistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!"; // Slightly different input

	Hasher::Blake2b blake2b;

	// Compute hash for input_data_1
	FIFO hash_1_fifo;
	auto hash_result_1 = blake2b.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_1.data()), input_data_1.size()), hash_1_fifo);
	ASSERT_TRUE(fn_name, hash_result_1);
	std::string hash_1 = StormByte::String::FromByteVector(hash_1_fifo.Data());

	// Compute hash for input_data_2
	FIFO hash_2_fifo;
	auto hash_result_2 = blake2b.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_2.data()), input_data_2.size()), hash_2_fifo);
	ASSERT_TRUE(fn_name, hash_result_2);
	std::string hash_2 = StormByte::String::FromByteVector(hash_2_fifo.Data());

	// Ensure the hashes are different
	ASSERT_NOT_EQUAL(fn_name, StormByte::String::FromByteVector(hash_1_fifo.Data()), StormByte::String::FromByteVector(hash_2_fifo.Data()));

	RETURN_TEST(fn_name, 0);
}

int TestBlake2bProducesDifferentContent() {
	const std::string fn_name = "TestBlake2bProducesDifferentContent";
	const std::string original_data = "Data to hash";

	Hasher::Blake2b blake2b;

	// Generate the hash
	FIFO hash;
	auto hash_result = blake2b.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), hash);
	ASSERT_TRUE(fn_name, hash_result);
	std::string hashed_data = StormByte::String::FromByteVector(hash.Data());

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

	Hasher::Blake2b blake2b;

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Hash the data asynchronously
	auto hash_consumer = blake2b.Hash(consumer);
	ASSERT_TRUE(fn_name, hash_consumer.IsWritable() || !hash_consumer.Empty());

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