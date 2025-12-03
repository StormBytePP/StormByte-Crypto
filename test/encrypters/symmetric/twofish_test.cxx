#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <iostream>

using namespace StormByte::Crypto;

int TestTwofishEncryptDecryptConsistency() {
	const std::string fn_name = "TestTwofishEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	const std::string password = "SecurePassword123!";

	Symmetric twofish(Algorithm::Symmetric::Twofish, password);

	// Encrypt
	auto encrypted = twofish.Encrypt(original);
	ASSERT_TRUE(fn_name, encrypted.has_value());
	ASSERT_FALSE(fn_name, encrypted.value().empty());

	// Decrypt
	auto decrypted = twofish.Decrypt(encrypted.value());
	ASSERT_TRUE(fn_name, decrypted.has_value());
	ASSERT_FALSE(fn_name, decrypted.value().empty());
	ASSERT_EQUAL(fn_name, decrypted.value(), original);

	RETURN_TEST(fn_name, 0);
}

int TestTwofishWrongDecryptionPassword() {
	const std::string fn_name = "TestTwofishWrongDecryptionPassword";
	const std::string original = "Twofish by Bruce Schneier is an AES finalist";
	const std::string password = "CorrectPassword";
	const std::string wrongPassword = "WrongPassword";

	Symmetric twofish(Algorithm::Symmetric::Twofish, password);
	Symmetric wrongTwofish(Algorithm::Symmetric::Twofish, wrongPassword);

	// Encrypt with correct password
	auto encrypted = twofish.Encrypt(original);
	ASSERT_TRUE(fn_name, encrypted.has_value());

	// Decrypt with wrong password
	// Note: PKCS#7 padding validation will typically detect wrong password
	auto decrypted = wrongTwofish.Decrypt(encrypted.value());

	// Either decryption fails (padding error) or succeeds with garbage data
	if (!decrypted.has_value()) {
		// Expected: padding error with wrong password
		RETURN_TEST(fn_name, 0);
	}

	// If decryption succeeds, verify the data does NOT match the original
	ASSERT_NOT_EQUAL(fn_name, decrypted.value(), original);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestTwofishEncryptDecryptConsistency();
	result += TestTwofishWrongDecryptionPassword();

	if (result == 0) {
		std::cout << "Twofish tests passed" << std::endl;
	} else {
		std::cout << "Twofish tests failed" << std::endl;
	}
	return result;
}
