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
#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/test_handlers.h>
#include <thread>
#include <iostream>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestECDSASignAndVerify() {
	const std::string fn_name = "TestECDSASignAndVerify";
	const std::string message = "This is a test message.";
	constexpr const unsigned short curve_bits = 256;
	// Generate a key pair
	auto keypair_result = KeyPair::ECDSA::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Signer::ECDSA ecdsa(keypair_result);
	// Sign the message
	FIFO signed_data;
	auto sign_result = ecdsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	std::string signature = StormByte::String::FromByteVector(signed_data.Data());
	// Verify the signature
	bool verify_result = ecdsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
	ASSERT_TRUE(fn_name, verify_result);
	RETURN_TEST(fn_name, 0);
}

int TestECDSAVerifyWithCorruptedSignature() {
	const std::string fn_name = "TestECDSAVerifyWithCorruptedSignature";
	const std::string message = "This is a test message.";
	constexpr const unsigned short curve_bits = 256;
	// Generate a key pair
	auto keypair_result = KeyPair::ECDSA::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Signer::ECDSA ecdsa(keypair_result);
	// Sign the message
	FIFO signed_data;
	auto sign_result = ecdsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	std::string signature = StormByte::String::FromByteVector(signed_data.Data());
	// Corrupt the signature
	if (!signature.empty()) {
		signature[0] = static_cast<char>(~signature[0]);
	}

	// Verify the corrupted signature
	bool verify_result = ecdsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
	ASSERT_FALSE(fn_name, verify_result);
	RETURN_TEST(fn_name, 0);
}

int TestECDSAVerifyWithMismatchedKey() {
	const std::string fn_name = "TestECDSAVerifyWithMismatchedKey";
	const std::string message = "This is a test message.";
	constexpr const unsigned short curve_bits = 256;
	// Generate two key pairs
	auto keypair_result = KeyPair::ECDSA::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Signer::ECDSA ecdsa(keypair_result);
	auto keypair_result_2 = KeyPair::ECDSA::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result_2);
	Signer::ECDSA ecdsa2(keypair_result_2);
	// Sign the message with the first private key
	FIFO signed_data;
	auto sign_result = ecdsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	std::string signature = StormByte::String::FromByteVector(signed_data.Data());
	// Verify the signature with the second public key
	bool verify_result = ecdsa2.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
	ASSERT_FALSE(fn_name, verify_result);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;
	result += TestECDSASignAndVerify();
	result += TestECDSAVerifyWithCorruptedSignature();
	result += TestECDSAVerifyWithMismatchedKey();
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}

	return result;
}
