#include <StormByte/crypto/crypter/symmetric/serpent.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <iostream>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestSerpentEncryptDecryptConsistency() {
	const std::string fn_name = "TestSerpentEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	const std::string password = "SecurePassword123!";

	Crypter::Serpent serpent(password);

	// Encrypt
	FIFO encrypted_d;
	auto encrypt_result = serpent.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);
	ASSERT_FALSE(fn_name, encrypted_d.Data().empty());

	// Decrypt
	FIFO decrypted_d;
	auto decrypt_result = serpent.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_d.Data().data()), encrypted_d.Data().size()), decrypted_d);
	ASSERT_TRUE(fn_name, decrypt_result);
	ASSERT_FALSE(fn_name, decrypted_d.Data().empty());
	ASSERT_EQUAL(fn_name, std::string(reinterpret_cast<const char*>(decrypted_d.Data().data()), decrypted_d.Data().size()), original);

	RETURN_TEST(fn_name, 0);
}

int TestSerpentWrongDecryptionPassword() {
	const std::string fn_name = "TestSerpentWrongDecryptionPassword";
	const std::string original = "Serpent is an AES finalist block cipher";
	const std::string password = "CorrectPassword";
	const std::string wrongPassword = "WrongPassword";

	Crypter::Serpent serpent(password);
	Crypter::Serpent wrongSerpent(wrongPassword);

	// Encrypt with correct password
	FIFO encrypted_d;
	auto encrypt_result = serpent.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);

	// Decrypt with wrong password
	// Note: PKCS#7 padding validation will typically detect wrong password
	FIFO decrypted_d;
	auto decrypt_result = wrongSerpent.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_d.Data().data()), encrypted_d.Data().size()), decrypted_d);

	// Either decryption fails (padding error) or succeeds with garbage data
	ASSERT_FALSE(fn_name, decrypt_result);

	// If decryption succeeds, verify the data does NOT match the original
	ASSERT_NOT_EQUAL(fn_name, std::string(reinterpret_cast<const char*>(decrypted_d.Data().data()), decrypted_d.Data().size()), original);

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
