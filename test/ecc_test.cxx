#include <StormByte/buffers/producer.hxx>
#include <StormByte/crypto/asymetric.hxx>
#include <StormByte/test_handlers.h>

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
	StormByte::Buffers::Simple encrypted_buffer = encrypted_future;

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
	StormByte::Buffers::Simple encrypted_buffer = encrypted_future;

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
	StormByte::Buffers::Simple encrypted_buffer = encrypted_future;

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
	StormByte::Buffers::Simple encrypted_buffer = encrypted_future;

	// Verify encrypted content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, std::string(reinterpret_cast<const char*>(encrypted_buffer.Data().data()), encrypted_buffer.Size()));

	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptDecryptInOneStep() {
    const std::string fn_name = "TestECCEncryptDecryptInOneStep";
    const std::string input_data = "This is the data to encrypt and decrypt in one step.";

    // Generate a key pair
    auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Asymmetric ecc(Algorithm::Asymmetric::ECC, keypair_result.value());

    // Create a producer buffer and write the input data
    StormByte::Buffers::Producer producer;
    producer << input_data;
    producer << StormByte::Buffers::Status::EoF; // Mark the producer as EOF

    // Create a consumer buffer from the producer
    StormByte::Buffers::Consumer consumer(producer.Consumer());

    // Encrypt the data asynchronously
    auto encrypted_consumer = ecc.Encrypt(consumer);

    // Decrypt the data asynchronously using the encrypted consumer
    auto decrypted_consumer = ecc.Decrypt(encrypted_consumer);

    // Wait for the decryption process to complete
    while (!decrypted_consumer.IsEoF()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Read the decrypted data from the decrypted_consumer
    std::string decrypted_data;
    while (true) {
        size_t available_bytes = decrypted_consumer.AvailableBytes();
        if (available_bytes == 0) {
            if (decrypted_consumer.IsEoF()) {
                break; // End of decrypted data
            } else {
                ASSERT_FALSE(fn_name, true); // Unexpected error
            }
        }

        auto read_result = decrypted_consumer.Read(available_bytes);
        if (!read_result.has_value()) {
            ASSERT_FALSE(fn_name, true); // Unexpected error
        }

        const auto& chunk = read_result.value();
        decrypted_data.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    }

    // Ensure the decrypted data matches the original input data
    ASSERT_EQUAL(fn_name, input_data, decrypted_data);

    RETURN_TEST(fn_name, 0);
}

int TestECCEncryptUsingConsumerProducer() {
    const std::string fn_name = "TestECCEncryptUsingConsumerProducer";
    const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";

    // Generate a key pair
    auto keypair_result = KeyPair::Generate(Algorithm::Asymmetric::ECC, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());

	Asymmetric ecc(Algorithm::Asymmetric::ECC, keypair_result.value());

    // Create a producer buffer and write the input data
    StormByte::Buffers::Producer producer;
    producer << input_data;
    producer << StormByte::Buffers::Status::EoF; // Mark the producer as EOF

    // Create a consumer buffer from the producer
    StormByte::Buffers::Consumer consumer(producer.Consumer());

    // Encrypt the data asynchronously
    auto encrypted_consumer = ecc.Encrypt(consumer);

    // Wait for the encryption process to complete
    while (!encrypted_consumer.IsEoF()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Read the encrypted data from the encrypted_consumer
    std::vector<std::byte> encrypted_data;
    while (true) {
        size_t available_bytes = encrypted_consumer.AvailableBytes();
        if (available_bytes == 0) {
            if (encrypted_consumer.IsEoF()) {
                break; // End of encrypted data
            } else {
                ASSERT_FALSE(fn_name, true); // Unexpected error
            }
        }

        auto read_result = encrypted_consumer.Read(available_bytes);
        if (!read_result.has_value()) {
            ASSERT_FALSE(fn_name, true); // Unexpected error
        }

        const auto& chunk = read_result.value();
        encrypted_data.insert(encrypted_data.end(), chunk.begin(), chunk.end());
    }
    ASSERT_FALSE(fn_name, encrypted_data.empty()); // Ensure encrypted data is not empty

    RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestECCEncryptDecrypt();
	result += TestECCDecryptionWithCorruptedData();
	result += TestECCDecryptWithMismatchedKey();
	result += TestECCWithCorruptedKeys();
	result += TestECCEncryptionProducesDifferentContent();
	result += TestECCEncryptDecryptInOneStep();
	result += TestECCEncryptUsingConsumerProducer();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
