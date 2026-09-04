/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 3
 * or later, as published by the Free Software Foundation.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#include <StormByte/crypto/crypter/symmetric/chachapoly.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"
#include <iostream>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestChaCha20EncryptDecryptConsistency() {
	const std::string fn_name = "TestChaCha20EncryptDecryptConsistency";
	Password password("SecurePassword123!");
	const std::string original_data = "Confidential information to encrypt and decrypt.";
	Crypter::ChaChaPoly chacha20(password);
	FIFO encrypted_d;
	auto encrypt_result = chacha20.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_d.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	FIFO decrypted_d;
	auto decrypt_result = chacha20.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_d);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_data = StormByte::String::FromByteVector(decrypted_d.Data());
	ASSERT_FALSE(fn_name, decrypted_data.empty());
	ASSERT_EQUAL(fn_name, decrypted_data, original_data);
	RETURN_TEST(fn_name, 0);
}
int TestChaCha20WrongDecryptionPassword() {
	const std::string fn_name = "TestChaCha20WrongDecryptionPassword";
	Password password("SecurePassword123!");
	Password wrong_password("WrongPassword456!");
	const std::string original_data = "This is sensitive data.";
	Crypter::ChaChaPoly chacha20(password);
	Crypter::ChaChaPoly chacha20_wrong(wrong_password);
	FIFO encrypted_d;
	auto encrypt_result = chacha20.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_d.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	FIFO decrypted_d;
	auto decrypt_result = chacha20_wrong.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_d);
	// Using AEAD (ChaCha20-Poly1305) means decryption with the wrong
	// password should fail authentication and return no value.
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestChaCha20CorruptedCiphertext() {
	const std::string fn_name = "TestChaCha20CorruptedCiphertext";
	Password password("SecurePassword123!");
	const std::string original_data = "Message to encrypt then corrupt a little.";
	Crypter::ChaChaPoly chacha(password);
	FIFO encrypted_d;
	auto encrypt_result = chacha.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_d.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	// Slightly corrupt the ciphertext (flip a single bit in the middle)
	std::string corrupted = encrypted_string; 
	if (!corrupted.empty()) {
		size_t pos = corrupted.size() / 2;
		corrupted[pos] = static_cast<char>(corrupted[pos] ^ 0x01);
	}
	FIFO decrypted_d;
	auto decrypt_result = chacha.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted.data()), corrupted.size()), decrypted_d);
	// AEAD should detect corruption and decryption should fail
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestChaCha20EncryptionProducesDifferentContent() {
	const std::string fn_name = "TestChaCha20EncryptionProducesDifferentContent";
	Password password("SecurePassword123!");
	const std::string original_data = "Important data to encrypt";
	Crypter::ChaChaPoly chacha(password);
	FIFO encrypted_data;
	auto encrypt_result = chacha.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()),
		encrypted_data
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	ASSERT_NOT_EQUAL(fn_name, encrypted_string, original_data);
	RETURN_TEST(fn_name, 0);
}
int main(int, char**) {
	int result = 0;
	result += TestChaCha20EncryptDecryptConsistency();
	result += TestChaCha20WrongDecryptionPassword();
	result += TestChaCha20CorruptedCiphertext();
	result += TestChaCha20EncryptionProducesDifferentContent();
	if (result == 0) {
		std::cout << "ChaCha20 tests passed" << std::endl;
	} else {
		std::cout << "ChaCha20 tests failed" << std::endl;
	}
	return result;
}
