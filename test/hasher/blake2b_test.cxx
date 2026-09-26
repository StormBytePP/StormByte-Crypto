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
#include <StormByte/crypto/hasher/blake2b.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

namespace {
	const std::string kExpectedHashThisString =
		"66CCD3A78741E16F894F2FB20045A8678D12B73D9CBA95D3473B1029781D6587"
		"648E839960BDA14F0FF075C0EC9E7ED1AA13197BEED8B027EEA32800453CC7F8";
}

// -------------------
// Correctness
// -------------------

int test_blake2b_hash_correctness() {
	const std::string fn_name = "test_blake2b_hash_correctness";
	const std::string input_data = "HashThisString";
	Hasher::Blake2b blake2b;
	FIFO hash;
	ASSERT_TRUE(fn_name, blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), hash));
	ASSERT_EQUAL(fn_name, kExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Distinct inputs
// -------------------

int test_blake2b_collision_resistance() {
	const std::string fn_name = "test_blake2b_collision_resistance";
	Hasher::Blake2b blake2b;
	FIFO hash_1_fifo;
	ASSERT_TRUE(fn_name, blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>("Original Input Data"), 19), hash_1_fifo));
	FIFO hash_2_fifo;
	ASSERT_TRUE(fn_name, blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>("Original Input Data!"), 20), hash_2_fifo));
	ASSERT_NOT_EQUAL(fn_name, DeserializeString(hash_1_fifo.Data()), DeserializeString(hash_2_fifo.Data()));
	RETURN_TEST(fn_name, 0);
}

int test_blake2b_produces_different_content() {
	const std::string fn_name = "test_blake2b_produces_different_content";
	const std::string original_data = "Data to hash";
	Hasher::Blake2b blake2b;
	FIFO hash;
	ASSERT_TRUE(fn_name, blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), hash));
	ASSERT_NOT_EQUAL(fn_name, original_data, DeserializeString(hash.Data()));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Stream
// -------------------

int test_blake2b_hash_using_consumer_producer() {
	const std::string fn_name = "test_blake2b_hash_using_consumer_producer";
	Hasher::Blake2b blake2b;
	StormByte::Buffer::Producer producer;
	producer.Write(std::string("HashThisString"));
	producer.Close();
	auto hash_consumer = blake2b.Hash(producer.Consumer());
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
	result += test_blake2b_hash_correctness();

	// -------------------
	// Distinct inputs
	// -------------------
	result += test_blake2b_collision_resistance();
	result += test_blake2b_produces_different_content();

	// -------------------
	// Stream
	// -------------------
	result += test_blake2b_hash_using_consumer_producer();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
