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

#include <StormByte/buffer/fifo.hxx>
#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/test_handlers.h>

#include <cstdint>
#include <string_view>
#include <vector>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Sign / verify
// -------------------

int test_rsa_sign_verify_success() {
	const std::string fn_name = "test_rsa_sign_verify_success";
	const std::string message = "This is a message to sign.";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(fn_name, rsa.Sign(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data));
	const std::string signature = DeserializeString(signed_data.Data());
	ASSERT_TRUE(fn_name, rsa.Verify(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signature));
	RETURN_TEST(fn_name, 0);
}

int test_rsa_sign_verify_byte_input_ranges() {
	const std::string fn_name = "test_rsa_sign_verify_byte_input_ranges";
	const std::string_view message = "This is a range message to sign.";
	const std::vector<std::uint8_t> bytes(message.begin(), message.end());
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(fn_name, rsa.Sign(message, signed_data));
	const std::string signature = DeserializeString(signed_data.Data());
	ASSERT_TRUE(fn_name, rsa.Verify(bytes, signature));
	ASSERT_TRUE(fn_name, rsa.Verify(std::span<const std::uint8_t>(bytes), signature));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Failure modes
// -------------------

int test_rsa_sign_verify_with_different_key_pair() {
	const std::string fn_name = "test_rsa_sign_verify_with_different_key_pair";
	const std::string message = "This is a message to sign.";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp2));
	Signer::RSA rsa2(kp2);
	FIFO signed_data;
	ASSERT_TRUE(fn_name, rsa.Sign(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data));
	const std::string signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(fn_name, rsa2.Verify(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signature));
	RETURN_TEST(fn_name, 0);
}

int test_rsa_sign_verify_with_corrupted_message() {
	const std::string fn_name = "test_rsa_sign_verify_with_corrupted_message";
	const std::string message = "This is a message to sign.";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(fn_name, rsa.Sign(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data));
	const std::string signature = DeserializeString(signed_data.Data());
	std::string corrupted_message = message;
	if (!corrupted_message.empty())
		corrupted_message[0] = static_cast<char>(~corrupted_message[0]);
	ASSERT_FALSE(fn_name, rsa.Verify(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(corrupted_message.data()), corrupted_message.size()), signature));
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Sign / verify
	// -------------------
	result += test_rsa_sign_verify_success();
	result += test_rsa_sign_verify_byte_input_ranges();

	// -------------------
	// Failure modes
	// -------------------
	result += test_rsa_sign_verify_with_different_key_pair();
	result += test_rsa_sign_verify_with_corrupted_message();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
