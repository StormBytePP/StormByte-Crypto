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

#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Round trip
// -------------------

int test_twofish_encrypt_decrypt_consistency() {
	const std::string fn_name = "test_twofish_encrypt_decrypt_consistency";
	const std::string original = "The quick brown fox jumps over the lazy dog";
	Password password("SecurePassword123!");
	Crypter::TwoFish twofish(password);
	FIFO encrypted_d;
	ASSERT_TRUE(fn_name, twofish.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_d));
	ASSERT_FALSE(fn_name, encrypted_d.Empty());
	FIFO decrypted_d;
	ASSERT_TRUE(fn_name, twofish.Decrypt(encrypted_d.Data(), decrypted_d));
	ASSERT_FALSE(fn_name, decrypted_d.Empty());
	ASSERT_EQUAL(fn_name, DeserializeString(decrypted_d.Data()), original);
	RETURN_TEST(fn_name, 0);
}

int test_twofish_encryption_produces_different_content() {
	const std::string fn_name = "test_twofish_encryption_produces_different_content";
	Password password("SecurePassword123!");
	const std::string original_data = "Important data to encrypt";
	Crypter::TwoFish twofish(password);
	FIFO encrypted_data;
	ASSERT_TRUE(fn_name, twofish.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data));
	const std::string encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	ASSERT_NOT_EQUAL(fn_name, encrypted_string, original_data);
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Failure modes
// -------------------

int test_twofish_wrong_decryption_password() {
	const std::string fn_name = "test_twofish_wrong_decryption_password";
	const std::string original = "Twofish by Bruce Schneier is an AES finalist";
	Password password("CorrectPassword");
	Password wrongPassword("WrongPassword");
	Crypter::TwoFish twofish(password);
	Crypter::TwoFish wrongTwofish(wrongPassword);
	FIFO encrypted_d;
	ASSERT_TRUE(fn_name, twofish.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original.data()), original.size()), encrypted_d));
	ASSERT_FALSE(fn_name, encrypted_d.Empty());
	FIFO decrypted_d;
	(void)wrongTwofish.Decrypt(encrypted_d.Data(), decrypted_d);
	ASSERT_NOT_EQUAL(fn_name, DeserializeString(decrypted_d.Data()), original);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Round trip
	// -------------------
	result += test_twofish_encrypt_decrypt_consistency();
	result += test_twofish_encryption_produces_different_content();

	// -------------------
	// Failure modes
	// -------------------
	result += test_twofish_wrong_decryption_password();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
