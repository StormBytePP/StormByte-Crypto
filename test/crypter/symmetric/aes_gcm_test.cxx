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

#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"
#include <iostream>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestAESGCMEncryptDecryptConsistency() {
	const std::string fn_name = "TestAESGCMEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	Password password("SecurePassword123!");
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
	Password password("CorrectPassword");
	Password wrongPassword("WrongPassword");
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
	Password password("MyPassword");
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
int TestAESGCMEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestAESGCMEncryptionProducesDifferentContent";
	Password password("SecurePassword123!");
	const std::string original_data = "Important data to encrypt";
	Crypter::AES_GCM aes_gcm(password);
	FIFO encrypted_data;
	auto encrypt_result = aes_gcm.Encrypt(
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
	result += TestAESGCMEncryptDecryptConsistency();
	result += TestAESGCMWrongPassword();
	result += TestAESGCMAuthenticationIntegrity();
	result += TestAESGCMEncryptionProducesDifferentContent();
	if (result == 0) {
		std::cout << "AES-GCM tests passed" << std::endl;
	} else {
		std::cout << "AES-GCM tests failed" << std::endl;
	}
	return result;
}
