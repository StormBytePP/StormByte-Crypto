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

#include <StormByte/buffer/fifo.hxx>
#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/test_handlers.h>
#include <thread>
#include <iostream>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestDSASignAndVerify(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestDSASignAndVerify";
	const std::string message = "This is a test message.";
	Signer::DSA dsa(kp);
	// Sign the message
	FIFO signed_data;
	auto sign_result = dsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	std::string signature = StormByte::String::FromByteVector(signed_data.Data());
	// Verify the signature
	bool verify_result = dsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
	ASSERT_TRUE(fn_name, verify_result);
	RETURN_TEST(fn_name, 0);
}

int TestDSAVerifyWithCorruptedSignature(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestDSAVerifyWithCorruptedSignature";
	const std::string message = "This is a test message.";
	Signer::DSA dsa(kp);
	// Sign the message
	FIFO signed_data;
	auto sign_result = dsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	std::string signature = StormByte::String::FromByteVector(signed_data.Data());
	// Corrupt the signature
	if (!signature.empty()) {
		signature[0] = static_cast<char>(~signature[0]);
	}

	// Verify the corrupted signature
	bool verify_result = dsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
	ASSERT_FALSE(fn_name, verify_result);
	RETURN_TEST(fn_name, 0);
}

int TestDSAVerifyWithMismatchedKey(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestDSAVerifyWithMismatchedKey";
	const std::string message = "This is a test message.";
	Signer::DSA dsa(kp);
	auto kp2 = KeyPair::DSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp2);
	Signer::DSA dsa2(kp2);
	FIFO signed_data;
	auto sign_result = dsa.Sign(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		signed_data
	);
	ASSERT_TRUE(fn_name, sign_result);
	std::string signature = StormByte::String::FromByteVector(signed_data.Data());
	bool verify_result = dsa2.Verify(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		signature
	);
	ASSERT_FALSE(fn_name, verify_result);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;
	const int key_strength = 2048;
	// Generate a single DSA keypair for all tests (key generation is expensive)
	auto keypair_result = KeyPair::DSA::Generate(key_strength);
	if (!keypair_result) {
		std::cerr << "Failed to generate DSA keypair" << std::endl;
		return 1;
	}

	auto kp = keypair_result;
	result += TestDSASignAndVerify(kp);
	result += TestDSAVerifyWithCorruptedSignature(kp);
	result += TestDSAVerifyWithMismatchedKey(kp);
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}

	return result;
}
