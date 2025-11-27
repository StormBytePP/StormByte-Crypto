#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/asymetric.hxx>
#include <StormByte/crypto/signer.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestRSAEncryptDecrypt() {
	const std::string fn_name = "TestRSAEncryptDecrypt";
	const std::string message = "This is a test message.";
	const int key_strength = 2048;

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Asymmetric rsa(Algorithm::Asymmetric::RSA, keypair_result.value());

	auto encrypt_result = rsa.Encrypt(message);
	if (!encrypt_result.has_value()) {
		RETURN_TEST(fn_name, 1);
	}

	auto encrypted_string = encrypt_result.value();

	auto decrypt_result = rsa.Decrypt(encrypted_string);
	if (!decrypt_result.has_value()) {
		RETURN_TEST(fn_name, 1);
	}
	std::string decrypted_message = decrypt_result.value();

	ASSERT_EQUAL(fn_name, message, decrypted_message);
	RETURN_TEST(fn_name, 0);
}

int TestRSADecryptionWithCorruptedData() {
	const std::string fn_name = "TestRSADecryptionWithCorruptedData";
	const std::string message = "Important message!";
	const int key_strength = 2048;

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Asymmetric rsa(Algorithm::Asymmetric::RSA, keypair_result.value());

	auto encrypt_result = rsa.Encrypt(message);
	if (!encrypt_result.has_value()) {
		RETURN_TEST(fn_name, 1);
	}

	auto encrypted_string = encrypt_result.value();

	auto corrupted_string = encrypted_string;
	if (!corrupted_string.empty()) {
		corrupted_string[0] = ~corrupted_string[0];
	}

	else {
		RETURN_TEST(fn_name, 1);
	}

	auto decrypt_result = rsa.Decrypt(corrupted_string);
	if (!decrypt_result.has_value()) {
		RETURN_TEST(fn_name, 0);
	}

	RETURN_TEST(fn_name, 1);
}

int TestRSADecryptWithMismatchedKey() {
	const std::string fn_name = "TestRSADecryptWithMismatchedKey";
	const std::string message = "Sensitive message.";
	const int key_strength = 2048;

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Asymmetric rsa(Algorithm::Asymmetric::RSA, keypair_result.value());

	auto keypair_result_2 = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result_2.has_value());
	Asymmetric rsa2(Algorithm::Asymmetric::RSA, keypair_result_2.value());

	auto encrypt_result = rsa.Encrypt(message);
	if (!encrypt_result.has_value()) {
		RETURN_TEST(fn_name, 1);
	}

	auto encrypted_string = encrypt_result.value();

	auto decrypt_result = rsa2.Decrypt(encrypted_string);
	if (!decrypt_result.has_value()) {
		RETURN_TEST(fn_name, 0);
	}

	RETURN_TEST(fn_name, 1);
}

int TestRSAWithCorruptedKeys() {
	const std::string fn_name = "TestRSAWithCorruptedKeys";
	const std::string message = "This is a test message.";
	const int key_strength = 2048;

	// Step 1: Generate a valid RSA key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Asymmetric rsa(Algorithm::Asymmetric::RSA, keypair_result.value());

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
	Asymmetric corrupted_rsa(Algorithm::Asymmetric::RSA, { corrupted_public_key, corrupted_private_key });

	// Step 4: Attempt encryption with the corrupted public key
	auto encrypt_result = corrupted_rsa.Encrypt(message);
	if (encrypt_result.has_value()) {
		std::cerr << "[" << fn_name << "] Encryption unexpectedly succeeded with corrupted public key.\n";
		RETURN_TEST(fn_name, 1);
	}

	// Step 5: Attempt decryption with the corrupted private key
	auto encrypted_future = rsa.Encrypt(message);
	if (!encrypted_future.has_value()) {
		RETURN_TEST(fn_name, 1); // Encryption with a valid key should not fail
	}

	auto encrypted_string = std::move(encrypted_future.value());
	auto decrypt_result = corrupted_rsa.Decrypt(encrypted_string);
	if (decrypt_result.has_value()) {
		std::cerr << "[" << fn_name << "] Decryption unexpectedly succeeded with corrupted private key.\n";
		RETURN_TEST(fn_name, 1);
	}

	// Step 6: Both operations failed gracefully
	RETURN_TEST(fn_name, 0);
}

int TestRSAEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestRSAEncryptionProducesDifferentContent";
	const std::string original_data = "Sensitive message";
	const int key_strength = 2048;

	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Asymmetric rsa(Algorithm::Asymmetric::RSA, keypair_result.value());

	// Encrypt the data
	auto encrypt_result = rsa.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, encrypted_string);

	RETURN_TEST(fn_name, 0);
}

int TestRSAEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestRSAEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	const int key_strength = 2048;

	// Generate a key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Asymmetric rsa(Algorithm::Asymmetric::RSA, keypair_result.value());

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();

	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());

	// Encrypt the data asynchronously
	auto encrypted_consumer = rsa.Encrypt(consumer);
	ASSERT_TRUE(fn_name, !encrypted_consumer.IsClosed() || !encrypted_consumer.Empty());

	// Decrypt the data asynchronously
	auto decrypted_consumer = rsa.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, !decrypted_consumer.IsClosed() || !decrypted_consumer.Empty());

	// Read the encrypted data from the encrypted_consumer
	auto decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty()); // Ensure decrypted data is not empty
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result); // Ensure decrypted data matches original input data

	RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifySuccess() {
	const std::string fn_name = "TestRSASignVerifySuccess";
	const std::string message = "This is a message to sign.";
	const int key_strength = 2048;

	// Generate a key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer rsa(Algorithm::Sign::RSA, keypair_result.value());

	// Sign the message
	auto sign_result = rsa.Sign(message);
	ASSERT_TRUE(fn_name, sign_result.has_value());
	std::string signature = sign_result.value();

	// Verify the signature
	bool verify_result = rsa.Verify(message, signature);
	ASSERT_TRUE(fn_name, verify_result);

	RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithDifferentKeyPair() {
	const std::string fn_name = "TestRSASignVerifyWithDifferentKeyPair";
	const std::string message = "This is a message to sign.";
	const int key_strength = 2048;

	// Generate two different key pairs
	auto keypair_result = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer rsa(Algorithm::Sign::RSA, keypair_result.value());

	auto keypair_result_2 = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result_2.has_value());
	Signer rsa2(Algorithm::Sign::RSA, keypair_result_2.value());

	// Sign the message with the first private key
	auto sign_result = rsa.Sign(message);
	ASSERT_TRUE(fn_name, sign_result.has_value());
	std::string signature = sign_result.value();

	// Attempt to verify the signature with the second public key
	bool verify_result = rsa2.Verify(message, signature);
	ASSERT_FALSE(fn_name, verify_result);

	RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithCorruptedMessage() {
	const std::string fn_name = "TestRSASignVerifyWithCorruptedMessage";
	const std::string message = "This is a message to sign.";
	const int key_strength = 2048;

	// Generate a key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer rsa(Algorithm::Sign::RSA, keypair_result.value());

	// Sign the message
	auto sign_result = rsa.Sign(message);
	ASSERT_TRUE(fn_name, sign_result.has_value());
	std::string signature = sign_result.value();

	// Corrupt the message
	std::string corrupted_message = message;
	if (!corrupted_message.empty()) {
		corrupted_message[0] = static_cast<char>(~corrupted_message[0]);
	}

	// Attempt to verify the signature with the corrupted message
	bool verify_result = rsa.Verify(corrupted_message, signature);
	ASSERT_FALSE(fn_name, verify_result);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestRSAEncryptDecrypt();
	result += TestRSASignVerifySuccess();
	result += TestRSASignVerifyWithDifferentKeyPair();
	result += TestRSASignVerifyWithCorruptedMessage();
	result += TestRSADecryptionWithCorruptedData();
	result += TestRSADecryptWithMismatchedKey();
	result += TestRSAWithCorruptedKeys();
	result += TestRSAEncryptionProducesDifferentContent();
	result += TestRSAEncryptDecryptUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}