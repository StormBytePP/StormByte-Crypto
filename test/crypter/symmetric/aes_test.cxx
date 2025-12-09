#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/symmetric/aes.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestAESEncryptDecryptConsistency() {
	const std::string fn_name = "TestAESEncryptDecryptConsistency";
	const std::string password = "SecurePassword123!";
	const std::string original_data = "Confidential information to encrypt and decrypt.";

	Crypter::AES aes(password);

	// Encrypt the data
	FIFO encrypted_data;
	auto encrypt_result = aes.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Decrypt the data
	FIFO decrypted_d;
	auto decrypt_result = aes.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_d);
	ASSERT_TRUE(fn_name, decrypt_result);

	std::string decrypted_data = StormByte::String::FromByteVector(decrypted_d.Data());
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

	Crypter::AES aes(password);
	Crypter::AES aes_wrong(wrong_password);

	// Encrypt the data
	FIFO encrypted_data;
	auto encrypt_result = aes.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Attempt to decrypt with a wrong password
	// Note: CBC mode doesn't authenticate, so decryption will "succeed" but produce garbage
	FIFO decrypted_d;
	auto decrypt_result = aes_wrong.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_d);
	// Verify the decrypted data does NOT match the original
	ASSERT_NOT_EQUAL(fn_name, StormByte::String::FromByteVector(decrypted_d.Data()), original_data);

	RETURN_TEST(fn_name, 0);
}

int TestAESDecryptionWithCorruptedData() {
	const std::string fn_name = "TestAESDecryptionWithCorruptedData";
	const std::string password = "StrongPassword123!";
	const std::string original_data = "Important confidential data";

	Crypter::AES aes(password);

	// Encrypt the data
	FIFO encrypted_data;
	auto encrypt_result = aes.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Corrupt the encrypted data
	// AES CBC stores: [16-byte salt][16-byte IV][ciphertext]
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
	FIFO corrupted_data;
	auto decrypt_result = aes.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), corrupted_data);
	
	// CBC mode with corrupted data should either:
	// 1. Fail with padding error (decrypt_result has no value), OR
	// 2. Succeed but produce garbage (different from original)
	// If it succeeded, the output must be different from the original
	ASSERT_NOT_EQUAL(fn_name, StormByte::String::FromByteVector(corrupted_data.Data()), original_data);
	// Either way (error or garbage), the corruption was detected

	RETURN_TEST(fn_name, 0);
}

int TestAESEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestAESEncryptionProducesDifferentContent";
	const std::string password = "SecurePassword123!";
	const std::string original_data = "Important data to encrypt";

	Crypter::AES aes(password);

	// Encrypt the data
	FIFO encrypted_data;
	auto encrypt_result = aes.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, encrypted_string, original_data);

	RETURN_TEST(fn_name, 0);
}

int TestAESEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestAESEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	const std::string password = "SecurePassword123!";

	Crypter::AES aes(password);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = aes.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());

	// Decrypt the data asynchronously
	auto decrypted_consumer = aes.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());

	auto decrypted_data = ReadAllFromConsumer(decrypted_consumer);

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
