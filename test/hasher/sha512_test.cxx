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
#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher/sha512.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

namespace {
	const std::string kExpectedHashThisString =
		"6D69A62B60C16398A2482B03FB56FB041E5014E3D8E1480833EB8427C3F45910"
		"B5B1ED812EC8C04087C92F47B50016C1495F358DD34E98723795E6E852B92875";
}

// -------------------
// Correctness
// -------------------

int test_sha512_hash_correctness() {
	const std::string fn_name = "test_sha512_hash_correctness";
	const std::string input_data = "HashThisString";
	Hasher::SHA512 sha512;
	FIFO hash_fifo;
	ASSERT_TRUE(fn_name, sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), hash_fifo));
	ASSERT_EQUAL(fn_name, kExpectedHashThisString, DeserializeString(hash_fifo.Data()));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Distinct inputs
// -------------------

int test_sha512_collision_resistance() {
	const std::string fn_name = "test_sha512_collision_resistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!";
	Hasher::SHA512 sha512;
	FIFO hash_fifo_1;
	ASSERT_TRUE(fn_name, sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_1.data()), input_data_1.size()), hash_fifo_1));
	FIFO hash_fifo_2;
	ASSERT_TRUE(fn_name, sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_2.data()), input_data_2.size()), hash_fifo_2));
	ASSERT_NOT_EQUAL(fn_name, DeserializeString(hash_fifo_1.Data()), DeserializeString(hash_fifo_2.Data()));
	RETURN_TEST(fn_name, 0);
}

int test_sha512_produces_different_content() {
	const std::string fn_name = "test_sha512_produces_different_content";
	const std::string original_data = "Data to hash";
	Hasher::SHA512 sha512;
	FIFO hash_fifo;
	ASSERT_TRUE(fn_name, sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), hash_fifo));
	ASSERT_NOT_EQUAL(fn_name, original_data, DeserializeString(hash_fifo.Data()));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Stream
// -------------------

int test_sha512_hash_using_consumer_producer() {
	const std::string fn_name = "test_sha512_hash_using_consumer_producer";
	const std::string input_data = "HashThisString";
	Hasher::SHA512 sha512;
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	auto hash_consumer = sha512.Hash(producer.Consumer());
	ASSERT_TRUE(fn_name, hash_consumer.IsWritable() || !hash_consumer.Empty());
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(fn_name, hash_result.Empty());
	ASSERT_EQUAL(fn_name, kExpectedHashThisString, DeserializeString(hash_result));
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Correctness
	// -------------------
	result += test_sha512_hash_correctness();

	// -------------------
	// Distinct inputs
	// -------------------
	result += test_sha512_collision_resistance();
	result += test_sha512_produces_different_content();

	// -------------------
	// Stream
	// -------------------
	result += test_sha512_hash_using_consumer_producer();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
