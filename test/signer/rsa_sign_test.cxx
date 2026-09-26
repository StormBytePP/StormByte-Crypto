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
#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/test_handlers.h>
#include <cstdint>
#include <iostream>
#include <string_view>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestRSASignVerifySuccess() {
    const std::string fn_name = "TestRSASignVerifySuccess";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;
    // Generate a key pair
    auto keypair_result = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result);
    Signer::RSA rsa(keypair_result);
    // Sign the message
	FIFO signed_data;
    auto sign_result = rsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());
    // Verify the signature
    bool verify_result = rsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
    ASSERT_TRUE(fn_name, verify_result);
    RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyByteInputRanges() {
    const std::string fn_name = "TestRSASignVerifyByteInputRanges";
    const std::string_view message = "This is a range message to sign.";
    const std::vector<std::uint8_t> bytes(message.begin(), message.end());
    auto keypair_result = KeyPair::RSA::Generate(2048);
    ASSERT_TRUE(fn_name, keypair_result);
    Signer::RSA rsa(keypair_result);
    FIFO signed_data;
    ASSERT_TRUE(fn_name, rsa.Sign(message, signed_data));
    const std::string signature = StormByte::String::FromByteVector(signed_data.Data());
    ASSERT_TRUE(fn_name, rsa.Verify(bytes, signature));
    ASSERT_TRUE(fn_name, rsa.Verify(std::span<const std::uint8_t>(bytes), signature));
    RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithDifferentKeyPair() {
    const std::string fn_name = "TestRSASignVerifyWithDifferentKeyPair";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;
    // Generate two different key pairs
    auto keypair_result = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result);
    Signer::RSA rsa(keypair_result);
    auto keypair_result_2 = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result_2);
    Signer::RSA rsa2(keypair_result_2);
    // Sign the message with the first private key
	FIFO signed_data;
    auto sign_result = rsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());
    // Verify the signature with the second public key
    bool verify_result = rsa2.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
    ASSERT_FALSE(fn_name, verify_result);
    RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithCorruptedMessage() {
    const std::string fn_name = "TestRSASignVerifyWithCorruptedMessage";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;
    // Generate a key pair
    auto keypair_result = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result);
    Signer::RSA rsa(keypair_result);
    // Sign the message
	FIFO signed_data;
    auto sign_result = rsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());
    // Corrupt the message
    std::string corrupted_message = message;
    if (!corrupted_message.empty()) {
        corrupted_message[0] = static_cast<char>(~corrupted_message[0]);
    }

    // Attempt to verify the signature with the corrupted message
    bool verify_result = rsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_message.data()), corrupted_message.size()), signature);
    ASSERT_FALSE(fn_name, verify_result);
    RETURN_TEST(fn_name, 0);
}

int main() {
    int result = 0;
    result += TestRSASignVerifySuccess();
    result += TestRSASignVerifyByteInputRanges();
    result += TestRSASignVerifyWithDifferentKeyPair();
    result += TestRSASignVerifyWithCorruptedMessage();
    if (result == 0) {
        std::cout << "All tests passed!" << std::endl;
    } else {
        std::cout << result << " tests failed." << std::endl;
    }

    return result;
}
