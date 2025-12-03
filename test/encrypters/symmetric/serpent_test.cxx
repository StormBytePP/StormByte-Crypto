#include <StormByte/crypto/symmetric.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <iostream>

using namespace StormByte::Crypto;

int TestSerpentEncryptDecryptConsistency() {
	const std::string fn_name = "TestSerpentEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	const std::string password = "SecurePassword123!";

	Symmetric serpent(Algorithm::Symmetric::Serpent, password);

	// Encrypt
	auto encrypted = serpent.Encrypt(original);
	ASSERT_TRUE(fn_name, encrypted.has_value());
	ASSERT_FALSE(fn_name, encrypted.value().empty());

	// Decrypt
	auto decrypted = serpent.Decrypt(encrypted.value());
	ASSERT_TRUE(fn_name, decrypted.has_value());
	ASSERT_FALSE(fn_name, decrypted.value().empty());
	ASSERT_EQUAL(fn_name, decrypted.value(), original);

	RETURN_TEST(fn_name, 0);
}

int TestSerpentWrongDecryptionPassword() {
	const std::string fn_name = "TestSerpentWrongDecryptionPassword";
	const std::string original = "Serpent is an AES finalist block cipher";
	const std::string password = "CorrectPassword";
	const std::string wrongPassword = "WrongPassword";

	Symmetric serpent(Algorithm::Symmetric::Serpent, password);
	Symmetric wrongSerpent(Algorithm::Symmetric::Serpent, wrongPassword);

	// Encrypt with correct password
	auto encrypted = serpent.Encrypt(original);
	ASSERT_TRUE(fn_name, encrypted.has_value());

	// Decrypt with wrong password
	// Note: PKCS#7 padding validation will typically detect wrong password
	auto decrypted = wrongSerpent.Decrypt(encrypted.value());

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

	result += TestSerpentEncryptDecryptConsistency();
	result += TestSerpentWrongDecryptionPassword();

	if (result == 0) {
		std::cout << "Serpent tests passed" << std::endl;
	} else {
		std::cout << "Serpent tests failed" << std::endl;
	}
	return result;
}
