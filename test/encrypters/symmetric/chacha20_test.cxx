#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <iostream>

using namespace StormByte::Crypto;

int TestChaCha20EncryptDecryptConsistency() {
	const std::string fn_name = "TestChaCha20EncryptDecryptConsistency";
	const std::string password = "SecurePassword123!";
	const std::string original_data = "Confidential information to encrypt and decrypt.";

	Symmetric chacha20(Algorithm::Symmetric::ChaCha20, password);

	auto encrypt_result = chacha20.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	auto decrypt_result = chacha20.Decrypt(encrypted_string);
	ASSERT_TRUE(fn_name, decrypt_result.has_value());

	std::string decrypted_data = decrypt_result.value();
	ASSERT_FALSE(fn_name, decrypted_data.empty());

	ASSERT_EQUAL(fn_name, original_data, decrypted_data);

	RETURN_TEST(fn_name, 0);
}

int TestChaCha20WrongDecryptionPassword() {
	const std::string fn_name = "TestChaCha20WrongDecryptionPassword";
	const std::string password = "SecurePassword123!";
	const std::string wrong_password = "WrongPassword456!";
	const std::string original_data = "This is sensitive data.";

	Symmetric chacha20(Algorithm::Symmetric::ChaCha20, password);
	Symmetric chacha20_wrong(Algorithm::Symmetric::ChaCha20, wrong_password);

	auto encrypt_result = chacha20.Encrypt(original_data);
	ASSERT_TRUE(fn_name, encrypt_result.has_value());

	auto encrypted_string = encrypt_result.value();
	ASSERT_FALSE(fn_name, encrypted_string.empty());

	auto decrypt_result = chacha20_wrong.Decrypt(encrypted_string);
	ASSERT_TRUE(fn_name, decrypt_result.has_value());
	ASSERT_NOT_EQUAL(fn_name, decrypt_result.value(), original_data);

	RETURN_TEST(fn_name, 0);
}

int main(int, char**) {
	int result = 0;

	result += TestChaCha20EncryptDecryptConsistency();
	result += TestChaCha20WrongDecryptionPassword();

	if (result == 0) {
		std::cout << "ChaCha20 tests passed" << std::endl;
	} else {
		std::cout << "ChaCha20 tests failed" << std::endl;
	}
	return result;
}
