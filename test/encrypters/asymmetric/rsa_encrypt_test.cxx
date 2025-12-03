#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/asymetric.hxx>
#include <StormByte/crypto/signer.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <thread>

using namespace StormByte::Crypto;

int TestRSAEncryptDecrypt(const KeyPair &kp) {
	const std::string fn_name = "TestRSAEncryptDecrypt";
	const std::string message = "This is a test message.";
	Asymmetric rsa(Algorithm::Asymmetric::RSA, kp);

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


int TestRSADecryptionWithCorruptedData(const KeyPair &kp) {
	const std::string fn_name = "TestRSADecryptionWithCorruptedData";
	const std::string message = "Important message!";
	Asymmetric rsa(Algorithm::Asymmetric::RSA, kp);

	auto encrypt_result = rsa.Encrypt(message);
	if (!encrypt_result.has_value()) {
		RETURN_TEST(fn_name, 1);
	}

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	// Corrupt the encrypted data
	auto corrupted_string = encrypted_string;
	if (!corrupted_string.empty()) {
		corrupted_string[0] = ~corrupted_string[0];
	}

	// Attempt to decrypt the corrupted data - should fail
	auto decrypt_result = rsa.Decrypt(corrupted_string);
	ASSERT_FALSE(fn_name, decrypt_result.has_value());

	RETURN_TEST(fn_name, 0);
}


int TestRSADecryptWithMismatchedKey(const KeyPair &kp) {
	const std::string fn_name = "TestRSADecryptWithMismatchedKey";
	const std::string message = "Sensitive message.";
	Asymmetric rsa(Algorithm::Asymmetric::RSA, kp);
	// Create mismatched by corrupting a copy of the public key instead of generating a new pair
	auto pub = kp.PublicKey();
	auto privOpt = kp.PrivateKey();
	std::string priv = privOpt.has_value() ? *privOpt : std::string();
	// Corrupt the private key to ensure decryption fails with rsa2
	if (!priv.empty()) {
		priv[0] = static_cast<char>(~priv[0]);
	}
	Asymmetric rsa2(Algorithm::Asymmetric::RSA, { pub, priv });

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


int TestRSAWithCorruptedKeys(const KeyPair &kp) {
	const std::string fn_name = "TestRSAWithCorruptedKeys";
	const std::string message = "This is a test message.";
	// Use supplied keypair
	Asymmetric rsa(Algorithm::Asymmetric::RSA, kp);

	// Step 2: Corrupt the public key (use supplied keypair)
	std::string corrupted_public_key = kp.PublicKey();
	if (!corrupted_public_key.empty()) {
		corrupted_public_key[0] = static_cast<char>(~corrupted_public_key[0]);
	}

	// Step 3: Corrupt the private key
	std::string corrupted_private_key = *kp.PrivateKey();
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


int TestRSAEncryptionProducesDifferentContent(const KeyPair &kp) {
	const std::string fn_name = "TestRSAEncryptionProducesDifferentContent";
	const std::string original_data = "Sensitive message";
	const int key_strength = 2048;
	Asymmetric rsa(Algorithm::Asymmetric::RSA, kp);

	// Encrypt the data
	auto encrypt_result = rsa.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, encrypted_string);

	RETURN_TEST(fn_name, 0);
}


int TestRSAEncryptDecryptUsingConsumerProducer(const KeyPair &kp) {
	const std::string fn_name = "TestRSAEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	const int key_strength = 2048;
	Asymmetric rsa(Algorithm::Asymmetric::RSA, kp);

	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	(void)producer.Write(input_data);
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
	auto kp_asym_result = KeyPair::Generate(Algorithm::Asymmetric::RSA, key_strength);
	if (!kp_asym_result.has_value()) {
		std::cerr << "Failed to generate RSA asymmetric keypair" << std::endl;
		return 1;
	}
	auto kp_asym = kp_asym_result.value();

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