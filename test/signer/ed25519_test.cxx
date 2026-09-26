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
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/test_handlers.h>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestEd25519GenerateKeyPair() {
	const std::string fn_name = "TestEd25519GenerateKeyPair";
	// Generate Ed25519 key pair (no curve name needed)
	auto keypair_result = KeyPair::ED25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);
	// Verify keys are generated and not empty
	ASSERT_TRUE(fn_name, keypair_result->PrivateKey().has_value());
	ASSERT_TRUE(fn_name, !keypair_result->PublicKey().empty());
	RETURN_TEST(fn_name, 0);
}

int TestEd25519SignAndVerify() {
	const std::string fn_name = "TestEd25519SignAndVerify";
	const std::string message = "Test message for Ed25519 signing";
	// Generate key pair
	auto keypair_result = KeyPair::ED25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);
	Signer::ED25519 signer(keypair_result);
	// Sign the message
	FIFO signed_data;
	auto sign_result = signer.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	// Verify the signature
	bool verified = signer.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), StormByte::String::FromByteVector(signed_data.Data()));
	ASSERT_TRUE(fn_name, verified);
	RETURN_TEST(fn_name, 0);
}

int TestEd25519VerifyWithWrongKey() {
	const std::string fn_name = "TestEd25519VerifyWithWrongKey";
	const std::string message = "Test message for Ed25519";
	// Generate two key pairs
	auto keypair_result1 = KeyPair::ED25519::Generate();
	auto keypair_result2 = KeyPair::ED25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result1);
	ASSERT_TRUE(fn_name, keypair_result2);
	Signer::ED25519 signer1(keypair_result1);
	Signer::ED25519 signer2(keypair_result2);
	// Sign with first key
	FIFO signed_data;
	auto sign_result = signer1.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	// Try to verify with second key (should fail)
	bool verified = signer2.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), StormByte::String::FromByteVector(signed_data.Data()));
	ASSERT_FALSE(fn_name, verified);
	RETURN_TEST(fn_name, 0);
}

int TestEd25519VerifyWithWrongMessage() {
	const std::string fn_name = "TestEd25519VerifyWithWrongMessage";
	const std::string message = "Original message";
	const std::string modified_message = "Modified message";
	// Generate key pair
	auto keypair_result = KeyPair::ED25519::Generate();
	ASSERT_TRUE(fn_name, keypair_result);
	Signer::ED25519 signer(keypair_result);
	// Sign the original message
	FIFO signed_data;
	auto sign_result = signer.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
	ASSERT_TRUE(fn_name, sign_result);
	// Try to verify modified message (should fail)
	bool verified = signer.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(modified_message.data()), modified_message.size()), StormByte::String::FromByteVector(signed_data.Data()));
	ASSERT_FALSE(fn_name, verified);
	RETURN_TEST(fn_name, 0);
}

int main() {
int result = 0;
result += TestEd25519GenerateKeyPair();
result += TestEd25519SignAndVerify();
result += TestEd25519VerifyWithWrongKey();
result += TestEd25519VerifyWithWrongMessage();
if (result == 0) {
std::cout << "All tests passed!" << std::endl;
} else {
std::cout << result << " tests failed." << std::endl;
}

return result;
}
