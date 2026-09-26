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

#include <StormByte/crypto/crypter/symmetric/serpent.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"
#include <iostream>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestSerpentEncryptDecryptConsistency() {
	const std::string fn_name = "TestSerpentEncryptDecryptConsistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	Password password("SecurePassword123!");
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
	Password password("CorrectPassword");
	Password wrongPassword("WrongPassword");
	Crypter::Serpent serpent(password);
	Crypter::Serpent wrongSerpent(wrongPassword);
	// Encrypt with correct password
	FIFO encrypted_d;
	auto encrypt_result = serpent.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_d);
	ASSERT_TRUE(fn_name, encrypt_result);
	// Decrypt with wrong password
	// Note: PKCS#7 padding validation will typically detect wrong password
	FIFO decrypted_d;
	[[maybe_unused]] auto decrypt_result = wrongSerpent.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_d.Data().data()), encrypted_d.Data().size()), decrypted_d);
	// Either decryption fails (padding error) or succeeds with garbage data
	// If decryption succeeds, verify the data does NOT match the original
	ASSERT_NOT_EQUAL(fn_name, std::string(reinterpret_cast<const char*>(decrypted_d.Data().data()), decrypted_d.Data().size()), original);
	RETURN_TEST(fn_name, 0);
}

int TestSerpentEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestSerpentEncryptionProducesDifferentContent";
	Password password("SecurePassword123!");
	const std::string original_data = "Important data to encrypt";
	Crypter::Serpent serpent(password);
	FIFO encrypted_data;
	auto encrypt_result = serpent.Encrypt(
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
	result += TestSerpentEncryptDecryptConsistency();
	result += TestSerpentWrongDecryptionPassword();
	result += TestSerpentEncryptionProducesDifferentContent();
	if (result == 0) {
		std::cout << "Serpent tests passed" << std::endl;
	} else {
		std::cout << "Serpent tests failed" << std::endl;
	}

	return result;
}
