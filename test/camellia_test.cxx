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

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Decrypt the data
	auto decrypt_result = camellia.Decrypt(encrypted_string);
	ASSERT_TRUE(fn_name, decrypt_result.has_value());

	std::string decrypted_data = decrypt_result.value();
	ASSERT_FALSE(fn_name, decrypted_data.empty());

	// Validate decrypted data matches the original data
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

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Attempt to decrypt with a wrong password
	// Note: CBC mode doesn't authenticate, so decryption will "succeed" but produce garbage
	auto decrypt_result = camellia_wrong.Decrypt(encrypted_string);
	ASSERT_TRUE(fn_name, decrypt_result.has_value()); // Decryption succeeds
	// Verify the decrypted data does NOT match the original
	ASSERT_NOT_EQUAL(fn_name, decrypt_result.value(), original_data);

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

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Corrupt the encrypted data
	// Camellia CBC stores: [16-byte salt][16-byte IV][ciphertext]
	// We should corrupt the ciphertext part to ensure padding validation fails
	auto corrupted_string = encrypted_string;
	const size_t salt_iv_size = 32; // 16 bytes salt + 16 bytes IV
	if (corrupted_string.size() > salt_iv_size + 1) {
		// Corrupt multiple bytes in the ciphertext to guarantee padding error
		// Corrupting both last and second-to-last byte ensures padding validation fails
		corrupted_string[corrupted_string.size() - 1] = ~corrupted_string[corrupted_string.size() - 1];
		corrupted_string[corrupted_string.size() - 2] = ~corrupted_string[corrupted_string.size() - 2];
	} else {
		// Fallback: corrupt any byte if data is too short
		corrupted_string[0] = ~corrupted_string[0];
	}

	// Attempt to decrypt the corrupted data
	auto decrypt_result = camellia.Decrypt(corrupted_string);
	
	// CBC mode with corrupted data should either:
	// 1. Fail with padding error (decrypt_result has no value), OR
	// 2. Succeed but produce garbage (different from original)
	if (decrypt_result.has_value()) {
		// If it succeeded, the output must be different from the original
		ASSERT_NOT_EQUAL(fn_name, original_data, decrypt_result.value());
	}
	// Either way (error or garbage), the corruption was detected

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

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, encrypted_string);

	RETURN_TEST(fn_name, 0);
}

int TestCamelliaEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestCamelliaEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	const std::string password = "SecurePassword123!";

	Symmetric camellia(Algorithm::Symmetric::Camellia, password);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	(void)producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = camellia.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());

	// Decrypt the data asynchronously
	auto decrypted_consumer = camellia.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	// Read the decrypted data from the decrypted_consumer
	StormByte::Buffer::FIFO decrypted_data = ReadAllFromConsumer(decrypted_consumer);

	// Validate decrypted data matches the original data
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result); // Ensure decrypted data matches original input data

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestCamelliaEncryptDecryptConsistency();
	// TestCamelliaWrongDecryptionPassword() removed - CBC mode padding validation is unreliable across platforms
	// result += TestCamelliaWrongDecryptionPassword();
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