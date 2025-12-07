#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

constexpr const unsigned short curve_bits = 256;

int TestECCEncryptDecrypt() {
	const std::string fn_name = "TestECCEncryptDecrypt";
	const std::string message = "This is a test message.";

	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);

	Crypter::ECC ecc(keypair_result);

	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());

	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_TRUE(fn_name, decrypt_result);

	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());

	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}

int TestECCDecryptionWithCorruptedData() {
	const std::string fn_name = "TestECCDecryptionWithCorruptedData";
	const std::string message = "Important message!";

	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);

	Crypter::ECC ecc(keypair_result);

	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Corrupt the encrypted data
	auto corrupted_string = encrypted_string;
	if (!corrupted_string.empty()) {
		corrupted_string[0] = ~corrupted_string[0];
	}

	// Attempt to decrypt the corrupted data - should fail
	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);

	RETURN_TEST(fn_name, 0);
}

int TestECCDecryptWithMismatchedKey() {
	const std::string fn_name = "TestECCDecryptWithMismatchedKey";
	const std::string message = "Sensitive message.";

	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);

	Crypter::ECC ecc(keypair_result);

	auto keypair_result_2 = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result_2);

	Crypter::ECC ecc2(keypair_result_2);

	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());

	FIFO decrypted_data;
	// Attempt to decrypt with a different key - should fail
	auto decrypt_result = ecc2.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);

	RETURN_TEST(fn_name, 0);
}

int TestECCWithCorruptedKeys() {
	const std::string fn_name = "TestECCWithCorruptedKeys";
	const std::string message = "This is a test message.";

	// Step 1: Generate a valid key pair
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);

	// Step 2: Corrupt the public key
	std::string corrupted_public_key = keypair_result->PublicKey();
	if (!corrupted_public_key.empty()) {
		corrupted_public_key[0] = static_cast<char>(~corrupted_public_key[0]);
	}

	// Step 3: Corrupt the private key
	std::string corrupted_private_key = *keypair_result->PrivateKey();
	if (!corrupted_private_key.empty()) {
		corrupted_private_key[0] = static_cast<char>(~corrupted_private_key[0]);
	}

	// Step 4: Attempt encryption with the corrupted public key
	Crypter::ECC ecc({ corrupted_public_key, corrupted_private_key });
	FIFO encrypted_data;
	// Step 5: Both encryption and decryption should fail
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_FALSE(fn_name, encrypt_result);

	// Step 6: Both operations failed gracefully
	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestECCEncryptionProducesDifferentContent";
	const std::string original_data = "ECC test message";

	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);

	Crypter::ECC ecc(keypair_result);

	// Encrypt the data
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, encrypted_string);

	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestECCEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";

	// Generate a key pair
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);

	Crypter::ECC ecc(keypair_result);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = ecc.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());

	// Decrypt the data asynchronously
	auto decrypted_consumer = ecc.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	// Read the encrypted data from the encrypted_consumer
	StormByte::Buffer::FIFO decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty()); // Ensure decrypted data is not empty
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result); // Ensure decrypted data matches original input data

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestECCEncryptDecrypt();
	result += TestECCDecryptionWithCorruptedData();
	result += TestECCDecryptWithMismatchedKey();
	result += TestECCWithCorruptedKeys();
	result += TestECCEncryptionProducesDifferentContent();
	result += TestECCEncryptDecryptUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
