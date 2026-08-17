#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"

#include <iostream>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestTwofishEncryptDecryptConsistency() {
	const std::string fn_name = "TestTwofishEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	Password password("SecurePassword123!");

	Crypter::TwoFish twofish(password);

	// Encrypt
	FIFO encrypted_d;
	auto encrypt_result = twofish.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);
	ASSERT_FALSE(fn_name, encrypted_d.Empty());

	// Decrypt
	FIFO decrypted_d;
	auto decrypt_result = twofish.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_d.Data().data()), encrypted_d.Data().size()), decrypted_d);
	ASSERT_TRUE(fn_name, decrypt_result);
	ASSERT_FALSE(fn_name, decrypted_d.Empty());
	ASSERT_EQUAL(fn_name, std::string(reinterpret_cast<const char*>(decrypted_d.Data().data()), decrypted_d.Data().size()), original);

	RETURN_TEST(fn_name, 0);
}

int TestTwofishWrongDecryptionPassword() {
	const std::string fn_name = "TestTwofishWrongDecryptionPassword";
	const std::string original = "Twofish by Bruce Schneier is an AES finalist";
	Password password("CorrectPassword");
	Password wrongPassword("WrongPassword");

	Crypter::TwoFish twofish(password);
	Crypter::TwoFish wrongTwofish(wrongPassword);

	// Encrypt with correct password
	FIFO encrypted_d;
	auto encrypt_result = twofish.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);
	ASSERT_FALSE(fn_name, encrypted_d.Empty());

	// Decrypt with wrong password
	// Note: PKCS#7 padding validation will typically detect wrong password
	FIFO decrypted_d;
	auto decrypt_result = wrongTwofish.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_d.Data().data()), encrypted_d.Data().size()), decrypted_d);

	// Either decryption fails (padding error) or succeeds with garbage data
	// If decryption succeeds, verify the data does NOT match the original
	ASSERT_NOT_EQUAL(fn_name, std::string(reinterpret_cast<const char*>(decrypted_d.Data().data()), decrypted_d.Data().size()), original);

	RETURN_TEST(fn_name, 0);
}

int TestTwofishEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestTwofishEncryptionProducesDifferentContent";
	Password password("SecurePassword123!");
	const std::string original_data = "Important data to encrypt";

	Crypter::TwoFish twofish(password);

	FIFO encrypted_data;
	auto encrypt_result = twofish.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()),
		encrypted_data
	);
	ASSERT_TRUE(fn_name, encrypt_result);

	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	ASSERT_NOT_EQUAL(fn_name, encrypted_string, original_data);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestTwofishEncryptDecryptConsistency();
	result += TestTwofishWrongDecryptionPassword();
	result += TestTwofishEncryptionProducesDifferentContent();

	if (result == 0) {
		std::cout << "Twofish tests passed" << std::endl;
	} else {
		std::cout << "Twofish tests failed" << std::endl;
	}
	return result;
}
