#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestRSAEncryptDecrypt(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecrypt";
	const std::string message = "This is a test message.";
	Crypter::RSA rsa(kp);

	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());

	FIFO decrypted_data;
	auto decrypt_result = rsa.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());

	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}


int TestRSADecryptionWithCorruptedData(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSADecryptionWithCorruptedData";
	const std::string message = "Important message!";
	Crypter::RSA rsa(kp);

	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
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
	auto decrypt_result = rsa.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);

	RETURN_TEST(fn_name, 0);
}


int TestRSADecryptWithMismatchedKey(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSADecryptWithMismatchedKey";
	const std::string message = "Sensitive message.";
	Crypter::RSA rsa(kp);
	// Create mismatched by corrupting a copy of the public key instead of generating a new pair
	auto pub = kp->PublicKey();
	auto priv = *kp->PrivateKey();
	// Corrupt the private key to ensure decryption fails with rsa2
	if (!priv.empty()) {
		priv[0] = static_cast<char>(~priv[0]);
	}
	Crypter::RSA rsa2({ pub, priv });

	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());

	FIFO decrypted_data;
	auto decrypt_result = rsa2.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);

	RETURN_TEST(fn_name, 0);
}


int TestRSAWithCorruptedKeys(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAWithCorruptedKeys";
	const std::string message = "This is a test message.";
	// Use supplied keypair
	Crypter::RSA rsa(kp);

	// Step 2: Corrupt the public key (use supplied keypair)
	std::string corrupted_public_key = kp->PublicKey();
	if (!corrupted_public_key.empty()) {
		corrupted_public_key[0] = static_cast<char>(~corrupted_public_key[0]);
	}

	// Step 3: Corrupt the private key
	std::string corrupted_private_key = *kp->PrivateKey();
	if (!corrupted_private_key.empty()) {
		corrupted_private_key[0] = static_cast<char>(~corrupted_private_key[0]);
	}
	Crypter::RSA corrupted_rsa({ corrupted_public_key, corrupted_private_key });

	// Step 4: Attempt encryption with the corrupted public key
	FIFO encrypted_data;
	auto encrypt_result = corrupted_rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_FALSE(fn_name, encrypt_result);

	// Step 5: Attempt decryption with the corrupted private key
	FIFO encrypted_data_valid;
	auto encrypt_result_valid = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data_valid);
	ASSERT_TRUE(fn_name, encrypt_result_valid);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data_valid.Data());
	FIFO decrypted_data;
	auto decrypt_result = corrupted_rsa.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);

	// Step 6: Both operations failed gracefully
	RETURN_TEST(fn_name, 0);
}


int TestRSAEncryptionProducesDifferentContent(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptionProducesDifferentContent";
	const std::string original_data = "Sensitive message";

	Crypter::RSA rsa(kp);

	// Encrypt the data
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, encrypted_string, original_data);

	RETURN_TEST(fn_name, 0);
}


int TestRSAEncryptDecryptUsingConsumerProducer(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";

	Crypter::RSA rsa(kp);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = rsa.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());

	// Decrypt the data asynchronously
	auto decrypted_consumer = rsa.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	// Read the encrypted data from the encrypted_consumer
	auto decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty()); // Ensure decrypted data is not empty
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result); // Ensure decrypted data matches original input data

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;
	const int key_strength = 2048;

	// Generate one keypair for asymmetric operations and one for signing
	auto kp_asym_result = KeyPair::RSA::Generate(key_strength);
	if (!kp_asym_result) {
		std::cerr << "Failed to generate RSA asymmetric keypair" << std::endl;
		return 1;
	}
	auto kp_asym = kp_asym_result;

	result += TestRSAEncryptDecrypt(kp_asym);
	result += TestRSADecryptionWithCorruptedData(kp_asym);
	result += TestRSADecryptWithMismatchedKey(kp_asym);
	result += TestRSAWithCorruptedKeys(kp_asym);
	result += TestRSAEncryptionProducesDifferentContent(kp_asym);
	result += TestRSAEncryptDecryptUsingConsumerProducer(kp_asym);

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}