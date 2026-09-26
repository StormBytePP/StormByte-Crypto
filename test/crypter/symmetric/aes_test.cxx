/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#include "helpers.hxx"

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/symmetric/aes.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Round trip
// -------------------

int test_aes_encrypt_decrypt_consistency() {
	const std::string fn_name = "test_aes_encrypt_decrypt_consistency";
	Password password("SecurePassword123!");
	const std::string original_data = "Confidential information to encrypt and decrypt.";
	Crypter::AES aes(password);
	FIFO encrypted_data;
	ASSERT_TRUE(fn_name, aes.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data));
	const std::string encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	FIFO decrypted_d;
	ASSERT_TRUE(fn_name, aes.Decrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_d));
	ASSERT_EQUAL(fn_name, original_data, DeserializeString(decrypted_d.Data()));
	RETURN_TEST(fn_name, 0);
}

int test_aes_encryption_produces_different_content() {
	const std::string fn_name = "test_aes_encryption_produces_different_content";
	Password password("SecurePassword123!");
	const std::string original_data = "Important data to encrypt";
	Crypter::AES aes(password);
	FIFO encrypted_data;
	ASSERT_TRUE(fn_name, aes.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data));
	const std::string encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	ASSERT_NOT_EQUAL(fn_name, encrypted_string, original_data);
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Failure modes
// -------------------

int test_aes_wrong_decryption_password() {
	const std::string fn_name = "test_aes_wrong_decryption_password";
	Password password("SecurePassword123!");
	Password wrong_password("WrongPassword456!");
	const std::string original_data = "This is sensitive data.";
	Crypter::AES aes(password);
	Crypter::AES aes_wrong(wrong_password);
	FIFO encrypted_data;
	ASSERT_TRUE(fn_name, aes.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data));
	const std::string encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	FIFO decrypted_d;
	(void)aes_wrong.Decrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_d);
	ASSERT_NOT_EQUAL(fn_name, DeserializeString(decrypted_d.Data()), original_data);
	RETURN_TEST(fn_name, 0);
}

int test_aes_decryption_with_corrupted_data() {
	const std::string fn_name = "test_aes_decryption_with_corrupted_data";
	Password password("StrongPassword123!");
	const std::string original_data = "Important confidential data";
	Crypter::AES aes(password);
	FIFO encrypted_data;
	ASSERT_TRUE(fn_name, aes.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data));
	std::string corrupted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(fn_name, corrupted_string.empty());
	const size_t salt_iv_size = 32;
	if (corrupted_string.size() > salt_iv_size + 1) {
		corrupted_string[corrupted_string.size() - 1] = static_cast<char>(~corrupted_string[corrupted_string.size() - 1]);
		corrupted_string[corrupted_string.size() - 2] = static_cast<char>(~corrupted_string[corrupted_string.size() - 2]);
	} else {
		corrupted_string[0] = static_cast<char>(~corrupted_string[0]);
	}
	FIFO corrupted_data;
	(void)aes.Decrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), corrupted_data);
	ASSERT_NOT_EQUAL(fn_name, DeserializeString(corrupted_data.Data()), original_data);
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Stream
// -------------------

int test_aes_encrypt_decrypt_using_consumer_producer() {
	const std::string fn_name = "test_aes_encrypt_decrypt_using_consumer_producer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	Password password("SecurePassword123!");
	Crypter::AES aes(password);
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	auto encrypted_consumer = aes.Encrypt(producer.Consumer());
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = aes.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	ASSERT_EQUAL(fn_name, input_data, DeserializeString(ReadAllFromConsumer(decrypted_consumer)));
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Round trip
	// -------------------
	result += test_aes_encrypt_decrypt_consistency();
	result += test_aes_encryption_produces_different_content();

	// -------------------
	// Failure modes
	// -------------------
	result += test_aes_wrong_decryption_password();
	result += test_aes_decryption_with_corrupted_data();

	// -------------------
	// Stream
	// -------------------
	result += test_aes_encrypt_decrypt_using_consumer_producer();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
