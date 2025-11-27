#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestAESEncryptDecryptConsistency() {
	const std::string fn_name = "TestAESEncryptDecryptConsistency";
	const std::string password = "SecurePassword123!";
	const std::string original_data = "Confidential information to encrypt and decrypt.";

	Symmetric aes(Algorithm::Symmetric::AES, password);

	// Encrypt the data
	auto encrypt_result = aes.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Decrypt the data
	auto decrypt_result = aes.Decrypt(encrypted_string);
	ASSERT_TRUE(fn_name, decrypt_result.has_value());

	std::string decrypted_data = decrypt_result.value();
	ASSERT_FALSE(fn_name, decrypted_data.empty());

	// Validate decrypted data matches the original data
	ASSERT_EQUAL(fn_name, original_data, decrypted_data);

	RETURN_TEST(fn_name, 0);
}

int TestAESWrongDecryptionPassword() {
	const std::string fn_name = "TestAESWrongDecryptionPassword";
	const std::string password = "SecurePassword123!";
	const std::string wrong_password = "WrongPassword456!";
	const std::string original_data = "This is sensitive data.";

	Symmetric aes(Algorithm::Symmetric::AES, password);
	Symmetric aes_wrong(Algorithm::Symmetric::AES, wrong_password);

	// Encrypt the data
	auto encrypt_result = aes.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Attempt to decrypt with a wrong password
	auto decrypt_result = aes_wrong.Decrypt(encrypted_string);
	ASSERT_FALSE(fn_name, decrypt_result.has_value()); // Decryption must fail

	RETURN_TEST(fn_name, 0);
}

int TestAESDecryptionWithCorruptedData() {
	const std::string fn_name = "TestAESDecryptionWithCorruptedData";
	const std::string password = "StrongPassword123!";
	const std::string original_data = "Important confidential data";

	Symmetric aes(Algorithm::Symmetric::AES, password);

	// Encrypt the data
	auto encrypt_result = aes.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Corrupt the encrypted data (flip a bit in the string)
	auto corrupted_string = encrypted_string;
	if (!corrupted_string.empty()) {
		corrupted_string[0] = ~corrupted_string[0]; // Flip the first byte
	}

	// Attempt to decrypt the corrupted data
	auto decrypt_result = aes.Decrypt(corrupted_string);
	ASSERT_FALSE(fn_name, decrypt_result.has_value()); // Decryption must fail

	RETURN_TEST(fn_name, 0);
}

int TestAESEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestAESEncryptionProducesDifferentContent";
	const std::string password = "SecurePassword123!";
	const std::string original_data = "Important data to encrypt";

	Symmetric aes(Algorithm::Symmetric::AES, password);

	// Encrypt the data
	auto encrypt_result = aes.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, encrypted_string);

	RETURN_TEST(fn_name, 0);
}

int TestAESEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestAESEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	const std::string password = "SecurePassword123!";

	Symmetric aes(Algorithm::Symmetric::AES, password);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = aes.Encrypt(consumer);
	ASSERT_TRUE(fn_name, !encrypted_consumer.IsClosed() || !encrypted_consumer.Empty());

	// Decrypt the data asynchronously
	auto decrypted_consumer = aes.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, !decrypted_consumer.IsClosed() || !decrypted_consumer.Empty());

	auto decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty()); // Ensure decrypted data is not empty

	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result); // Ensure decrypted data matches original input data

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestAESEncryptDecryptConsistency();
	result += TestAESWrongDecryptionPassword();
	result += TestAESDecryptionWithCorruptedData();
	result += TestAESEncryptionProducesDifferentContent();
	result += TestAESEncryptDecryptUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
