#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <iostream>

using namespace StormByte::Crypto;

int TestAESGCMEncryptDecryptConsistency() {
	const std::string fn_name = "TestAESGCMEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	const std::string password = "SecurePassword123!";

	Symmetric aes_gcm(Algorithm::Symmetric::AES_GCM, password);

	// Encrypt
	auto encrypted = aes_gcm.Encrypt(original);
	ASSERT_TRUE(fn_name, encrypted.has_value());
	ASSERT_FALSE(fn_name, encrypted.value().empty());

	// Decrypt
	auto decrypted = aes_gcm.Decrypt(encrypted.value());
	ASSERT_TRUE(fn_name, decrypted.has_value());
	ASSERT_FALSE(fn_name, decrypted.value().empty());
	ASSERT_EQUAL(fn_name, decrypted.value(), original);

	RETURN_TEST(fn_name, 0);
}

int TestAESGCMWrongPassword() {
	const std::string fn_name = "TestAESGCMWrongPassword";
	const std::string original = "AES-GCM provides authenticated encryption";
	const std::string password = "CorrectPassword";
	const std::string wrongPassword = "WrongPassword";

	Symmetric aes_gcm(Algorithm::Symmetric::AES_GCM, password);
	Symmetric wrongAESGCM(Algorithm::Symmetric::AES_GCM, wrongPassword);

	// Encrypt with correct password
	auto encrypted = aes_gcm.Encrypt(original);
	ASSERT_TRUE(fn_name, encrypted.has_value());

	// Decrypt with wrong password should FAIL (authentication error)
	// Unlike CBC mode, GCM will detect the authentication tag mismatch
	auto decrypted = wrongAESGCM.Decrypt(encrypted.value());

	// GCM authentication should fail with wrong password
	ASSERT_FALSE(fn_name, decrypted.has_value());

	RETURN_TEST(fn_name, 0);
}

int TestAESGCMAuthenticationIntegrity() {
	const std::string fn_name = "TestAESGCMAuthenticationIntegrity";
	const std::string original = "Data integrity is crucial";
	const std::string password = "MyPassword";

	Symmetric aes_gcm(Algorithm::Symmetric::AES_GCM, password);

	// Encrypt
	auto encrypted = aes_gcm.Encrypt(original);
	ASSERT_TRUE(fn_name, encrypted.has_value());

	// Corrupt a byte in the ciphertext (after salt+IV)
	std::string corrupted = encrypted.value();
	if (corrupted.size() > 30) {
		corrupted[30] = ~corrupted[30];  // Flip bits
	}

	// Decryption should fail due to authentication tag mismatch
	auto decrypted = aes_gcm.Decrypt(corrupted);
	ASSERT_FALSE(fn_name, decrypted.has_value());

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
