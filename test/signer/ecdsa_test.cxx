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
