#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestCamelliaEncryptDecryptConsistency() {
	const std::string fn_name = "TestCamelliaEncryptDecryptConsistency";
	const std::string password = "SecurePassword123!";
	const std::string original_data = "Confidential information to encrypt and decrypt.";

	Symmetric camellia(Algorithm::Symmetric::Camellia, password);

	// Encrypt the data
	auto encrypt_result = camellia.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;
	ASSERT_FALSE(fn_name, encrypted_buffer.Empty());

	// Decrypt the data
	auto decrypt_result = camellia.Decrypt(encrypted_buffer);
	ASSERT_TRUE(fn_name, decrypt_result.has_value());

	auto decrypted_future = std::move(decrypt_result.value());
	StormByte::Buffer::Simple decrypted_buffer = decrypted_future;
	ASSERT_FALSE(fn_name, decrypted_buffer.Empty());

	// Validate decrypted data matches the original data
	std::string decrypted_data(reinterpret_cast<const char*>(decrypted_buffer.Data().data()), decrypted_buffer.Size());
	ASSERT_EQUAL(fn_name, original_data, decrypted_data);

	RETURN_TEST(fn_name, 0);
}

int TestCamelliaWrongDecryptionPassword() {
	const std::string fn_name = "TestCamelliaWrongDecryptionPassword";
	const std::string password = "SecurePassword123!";
	const std::string wrong_password = "WrongPassword456!";
	const std::string original_data = "This is sensitive data.";

	Symmetric camellia(Algorithm::Symmetric::Camellia, password);
	Symmetric camellia_wrong(Algorithm::Symmetric::Camellia, wrong_password);

	// Encrypt the data
	auto encrypt_result = camellia.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;
	ASSERT_FALSE(fn_name, encrypted_buffer.Empty());

	// Attempt to decrypt with a wrong password
	auto decrypt_result = camellia_wrong.Decrypt(encrypted_buffer);
	ASSERT_FALSE(fn_name, decrypt_result.has_value()); // Decryption must fail

	RETURN_TEST(fn_name, 0);
}

int TestCamelliaDecryptionWithCorruptedData() {
	const std::string fn_name = "TestCamelliaDecryptionWithCorruptedData";
	const std::string password = "StrongPassword123!";
	const std::string original_data = "Important confidential data";

	Symmetric camellia(Algorithm::Symmetric::Camellia, password);

	// Encrypt the data
	auto encrypt_result = camellia.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;
	ASSERT_FALSE(fn_name, encrypted_buffer.Empty());

	// Corrupt the encrypted data (flip a bit in the buffer)
	auto corrupted_buffer = encrypted_buffer;
	auto corrupted_span = corrupted_buffer.Span();
	if (!corrupted_span.empty()) {
		corrupted_span[0] = std::byte(static_cast<uint8_t>(~std::to_integer<uint8_t>(corrupted_span[0]))); // Flip the first byte
	}

	// Attempt to decrypt the corrupted data
	auto decrypt_result = camellia.Decrypt(corrupted_buffer);
	ASSERT_FALSE(fn_name, decrypt_result.has_value()); // Decryption must fail

	RETURN_TEST(fn_name, 0);
}

int TestCamelliaEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestCamelliaEncryptionProducesDifferentContent";
	const std::string password = "SecurePassword123!";
	const std::string original_data = "Important data to encrypt";

	Symmetric camellia(Algorithm::Symmetric::Camellia, password);

	// Encrypt the data
	auto encrypt_result = camellia.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_future = std::move(encrypt_result.value());
	StormByte::Buffer::Simple encrypted_buffer = encrypted_future;
	ASSERT_FALSE(fn_name, encrypted_buffer.Empty());

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, std::string(reinterpret_cast<const char*>(encrypted_buffer.Data().data()), encrypted_buffer.Size()));

	RETURN_TEST(fn_name, 0);
}

int TestCamelliaEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestCamelliaEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	const std::string password = "SecurePassword123!";

	Symmetric camellia(Algorithm::Symmetric::Camellia, password);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer << input_data;
	producer << StormByte::Buffer::Status::ReadOnly; // Mark the producer as EOF

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = camellia.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsReadable());

	// Decrypt the data asynchronously
	auto decrypted_consumer = camellia.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsReadable());

	// Read the decrypted data from the decrypted_consumer
	StormByte::Buffer::Simple decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty()); // Ensure encrypted data is not empty

	// Validate decrypted data matches the original data
	std::string decrypted_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypted_result); // Ensure decrypted data matches original input data

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestCamelliaEncryptDecryptConsistency();
	result += TestCamelliaWrongDecryptionPassword();
	result += TestCamelliaDecryptionWithCorruptedData();
	result += TestCamelliaEncryptionProducesDifferentContent();
	result += TestCamelliaEncryptDecryptUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}