#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/asymetric.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

const std::string curve_name = "secp256r1";

int TestECCEncryptDecrypt() {
	const std::string fn_name = "TestECCEncryptDecrypt";
	const std::string message = "This is a test message.";

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Asymmetric ecc(Algorithm::Asymmetric::ECC, keypair_result.value());

	auto encrypt_result = ecc.Encrypt(message);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;

	auto decrypt_result = ecc.Decrypt(encrypted_buffer);
	ASSERT_TRUE(fn_name, decrypt_result.has_value());

	std::string decrypted_message = reinterpret_cast<const char*>(decrypt_result.value().Data().data());

	ASSERT_EQUAL(fn_name, message, decrypted_message);
	RETURN_TEST(fn_name, 0);
}

int TestECCDecryptionWithCorruptedData() {
	const std::string fn_name = "TestECCDecryptionWithCorruptedData";
	const std::string message = "Important message!";

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Asymmetric ecc(Algorithm::Asymmetric::ECC, keypair_result.value());

	auto encrypt_result = ecc.Encrypt(message);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;

	auto corrupted_buffer = encrypted_buffer;
	auto corrupted_span = corrupted_buffer.Span();
	if (!corrupted_span.empty()) {
		corrupted_span[0] = std::byte(static_cast<uint8_t>(~std::to_integer<uint8_t>(corrupted_span[0])));
	} else {
		RETURN_TEST(fn_name, 1);
	}

	auto decrypt_result = ecc.Decrypt(corrupted_buffer);
	ASSERT_FALSE(fn_name, decrypt_result.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECCDecryptWithMismatchedKey() {
	const std::string fn_name = "TestECCDecryptWithMismatchedKey";
	const std::string message = "Sensitive message.";

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Asymmetric ecc(Algorithm::Asymmetric::ECC, keypair_result.value());

	auto keypair_result_2 = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result_2.has_value());

	Asymmetric ecc2(Algorithm::Asymmetric::ECC, keypair_result_2.value());

	auto encrypt_result = ecc.Encrypt(message);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;

	auto decrypt_result = ecc2.Decrypt(encrypted_buffer);
	ASSERT_FALSE(fn_name, decrypt_result.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestECCWithCorruptedKeys() {
	const std::string fn_name = "TestECCWithCorruptedKeys";
	const std::string message = "This is a test message.";

	// Step 1: Generate a valid key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	// Step 2: Corrupt the public key
	std::string corrupted_public_key = keypair_result.value().PublicKey();
	if (!corrupted_public_key.empty()) {
		corrupted_public_key[0] = static_cast<char>(~corrupted_public_key[0]);
	}

	// Step 3: Corrupt the private key
	std::string corrupted_private_key = *keypair_result.value().PrivateKey();
	if (!corrupted_private_key.empty()) {
		corrupted_private_key[0] = static_cast<char>(~corrupted_private_key[0]);
	}

	// Step 4: Attempt encryption with the corrupted public key
	Asymmetric ecc(Algorithm::Asymmetric::ECC, { corrupted_public_key, corrupted_private_key });
	auto encrypt_result = ecc.Encrypt(message);
	ASSERT_FALSE(fn_name, encrypt_result.has_value());

	// Step 6: Both operations failed gracefully
	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestECCEncryptionProducesDifferentContent";
	const std::string original_data = "ECC test message";

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Asymmetric ecc(Algorithm::Asymmetric::ECC, keypair_result.value());

	// Encrypt the data
	auto encrypt_result = ecc.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());
	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, std::string(reinterpret_cast<const char*>(encrypted_buffer.Data().data()), encrypted_buffer.Size()));

	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestECCEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";

	// Generate a key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Asymmetric ecc(Algorithm::Asymmetric::ECC, keypair_result.value());

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer << input_data;
	producer << StormByte::Buffer::Status::ReadOnly; // Mark the producer as EOF

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = ecc.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsReadable());

	// Decrypt the data asynchronously
	auto decrypted_consumer = ecc.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsReadable());

	// Read the encrypted data from the encrypted_consumer
	StormByte::Buffer::Simple decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty()); // Ensure decrypted data is not empty
	std::string decrypted_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypted_result); // Ensure decrypted data matches original input data

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
