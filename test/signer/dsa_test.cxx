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
#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/test_handlers.h>

#include <iostream>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Sign / verify
// -------------------

int test_dsa_sign_and_verify(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "test_dsa_sign_and_verify";
	const std::string message = "This is a test message.";
	Signer::DSA dsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(fn_name, dsa.Sign(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data));
	const std::string signature = DeserializeString(signed_data.Data());
	ASSERT_TRUE(fn_name, dsa.Verify(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signature));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Failure modes
// -------------------

int test_dsa_verify_with_corrupted_signature(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "test_dsa_verify_with_corrupted_signature";
	const std::string message = "This is a test message.";
	Signer::DSA dsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(fn_name, dsa.Sign(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data));
	std::string signature = DeserializeString(signed_data.Data());
	if (!signature.empty())
		signature[0] = static_cast<char>(~signature[0]);
	ASSERT_FALSE(fn_name, dsa.Verify(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signature));
	RETURN_TEST(fn_name, 0);
}

int test_dsa_verify_with_mismatched_key(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "test_dsa_verify_with_mismatched_key";
	const std::string message = "This is a test message.";
	Signer::DSA dsa(kp);
	auto kp2 = KeyPair::DSA::Generate(2048);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp2));
	Signer::DSA dsa2(kp2);
	FIFO signed_data;
	ASSERT_TRUE(fn_name, dsa.Sign(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data));
	const std::string signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(fn_name, dsa2.Verify(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(message.data()), message.size()), signature));
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;
	auto kp = KeyPair::DSA::Generate(2048);
	if (!kp) {
		std::cerr << "Failed to generate DSA keypair" << std::endl;
		return 1;
	}

	// -------------------
	// Sign / verify
	// -------------------
	result += test_dsa_sign_and_verify(kp);

	// -------------------
	// Failure modes
	// -------------------
	result += test_dsa_verify_with_corrupted_signature(kp);
	result += test_dsa_verify_with_mismatched_key(kp);

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
