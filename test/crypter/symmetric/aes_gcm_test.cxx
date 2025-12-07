#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <iostream>

using StormByte::Buffer::FIFO;

using namespace StormByte::Crypto;

int TestAESGCMEncryptDecryptConsistency() {
	const std::string fn_name = "TestAESGCMEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	const std::string password = "SecurePassword123!";

	Crypter::AES_GCM aes_gcm(password);

	// Encrypt
	FIFO encrypted_data;
	auto encrypted = aes_gcm.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypted);
	ASSERT_FALSE(fn_name, encrypted_data.Empty());

	// Decrypt
	FIFO decrypted_data;
	auto decrypted = aes_gcm.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_data.Data().data()), encrypted_data.Data().size()), decrypted_data);
	ASSERT_TRUE(fn_name, decrypted);
	ASSERT_FALSE(fn_name, decrypted_data.Empty());
	ASSERT_EQUAL(fn_name, std::string(reinterpret_cast<const char*>(decrypted_data.Data().data()), decrypted_data.Data().size()), original);
	RETURN_TEST(fn_name, 0);
}

int TestAESGCMWrongPassword() {
	const std::string fn_name = "TestAESGCMWrongPassword";
	const std::string original = "AES-GCM provides authenticated encryption";
	const std::string password = "CorrectPassword";
	const std::string wrongPassword = "WrongPassword";

	Crypter::AES_GCM aes_gcm(password);
	Crypter::AES_GCM wrongAESGCM(wrongPassword);

	// Encrypt with correct password
	FIFO encrypted_data;
	auto encrypted = aes_gcm.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypted);

	// Decrypt with wrong password should FAIL (authentication error)
	// Unlike CBC mode, GCM will detect the authentication tag mismatch
	auto decrypted = wrongAESGCM.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_data.Data().data()), encrypted_data.Data().size()), encrypted_data);

	// GCM authentication should fail with wrong password
	ASSERT_FALSE(fn_name, decrypted);

	RETURN_TEST(fn_name, 0);
}

int TestAESGCMAuthenticationIntegrity() {
	const std::string fn_name = "TestAESGCMAuthenticationIntegrity";
	const std::string original = "Data integrity is crucial";
	const std::string password = "MyPassword";

	Crypter::AES_GCM aes_gcm(password);

	// Encrypt
	FIFO encrypted_data;
	auto encrypted = aes_gcm.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypted);

	// Corrupt a byte in the ciphertext (after salt+IV)
	std::string corrupted = StormByte::String::FromByteVector(encrypted_data.Data());
	if (corrupted.size() > 30) {
		corrupted[30] = ~corrupted[30];  // Flip bits
	}

	// Decryption should fail due to authentication tag mismatch
	FIFO corrupted_data;
	auto decrypted = aes_gcm.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted.data()), corrupted.size()), corrupted_data);
	ASSERT_FALSE(fn_name, decrypted);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestAESGCMEncryptDecryptConsistency();
	result += TestAESGCMWrongPassword();
	result += TestAESGCMAuthenticationIntegrity();

	if (result == 0) {
		std::cout << "AES-GCM tests passed" << std::endl;
	} else {
		std::cout << "AES-GCM tests failed" << std::endl;
	}
	return result;
}
