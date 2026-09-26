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
#include <StormByte/crypto/hasher/blake2s.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"
#include <thread>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestBlake2sHashCorrectness() {
	const std::string fn_name = "TestBlake2sHashCorrectness";
	const std::string input_data = "HashThisString";
	// Correct expected Blake2s hash value (uppercase, split into two lines for readability)
	const std::string expected_hash = 
		"542412C16951C1538BDCB190255C363F7FA1986B500FFBAB8377EF5E67785F1D";
	Hasher::Blake2s blake2s;
	// Compute hash for the input string
	FIFO hash;
	auto hash_result = blake2s.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), hash);
	ASSERT_TRUE(fn_name, hash_result);
	std::string actual_hash = StormByte::String::FromByteVector(hash.Data());
	// Validate the hash matches the expected value
	ASSERT_EQUAL(fn_name, expected_hash, actual_hash);
	RETURN_TEST(fn_name, 0);
}

int TestBlake2sCollisionResistance() {
	const std::string fn_name = "TestBlake2sCollisionResistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!"; // Slightly different input
	Hasher::Blake2s blake2s;
	// Compute hash for input_data_1
	FIFO hash_1_fifo;
	auto hash_result_1 = blake2s.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_1.data()), input_data_1.size()), hash_1_fifo);
	ASSERT_TRUE(fn_name, hash_result_1);
	std::string hash_1 = StormByte::String::FromByteVector(hash_1_fifo.Data());
	// Compute hash for input_data_2
	FIFO hash_2_fifo;
	auto hash_result_2 = blake2s.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(input_data_2.data()), input_data_2.size()), hash_2_fifo);
	ASSERT_TRUE(fn_name, hash_result_2);
	std::string hash_2 = StormByte::String::FromByteVector(hash_2_fifo.Data());
	// Ensure the hashes are different
	ASSERT_NOT_EQUAL(fn_name, hash_1, hash_2);
	RETURN_TEST(fn_name, 0);
}

int TestBlake2sProducesDifferentContent() {
	const std::string fn_name = "TestBlake2sProducesDifferentContent";
	const std::string original_data = "Data to hash";
	Hasher::Blake2s blake2s;
	// Generate the hash
	FIFO hash;
	auto hash_result = blake2s.Hash(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), hash);
	ASSERT_TRUE(fn_name, hash_result);
	std::string hashed_data = StormByte::String::FromByteVector(hash.Data());
	// Verify hashed content is different from original
	ASSERT_NOT_EQUAL(fn_name, original_data, hashed_data);
	RETURN_TEST(fn_name, 0);
}

int TestBlake2sHashUsingConsumerProducer() {
	const std::string fn_name = "TestBlake2sHashUsingConsumerProducer";
	const std::string input_data = "HashThisString";
	// Expected Blake2s hash value (from TestBlake2sHashCorrectness)
	const std::string expected_hash = "542412C16951C1538BDCB190255C363F7FA1986B500FFBAB8377EF5E67785F1D";
	Hasher::Blake2s blake2s;
	// Create a producer buffer and write the input data
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	// Create a consumer buffer from the producer
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	// Hash the data asynchronously
	auto hash_consumer = blake2s.Hash(consumer);
	ASSERT_TRUE(fn_name, hash_consumer.IsWritable() || !hash_consumer.Empty());
	// Read the hash result from the hash_consumer
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(fn_name, hash_result.Empty());
	// Deserialize the hash result
	std::string hash_result_str = DeserializeString(hash_result);
	ASSERT_EQUAL(fn_name, expected_hash, hash_result_str);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;
	result += TestBlake2sHashCorrectness();
	result += TestBlake2sCollisionResistance();
	result += TestBlake2sProducesDifferentContent();
	result += TestBlake2sHashUsingConsumerProducer();
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}

	return result;
}
