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
#include <StormByte/crypto/hasher/sha256.hxx>
#include <StormByte/test_handlers.h>

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Correctness
// -------------------

int test_sha256_hash_correctness() {
	const std::string fn_name = "test_sha256_hash_correctness";
	const std::string input_data = "HashThisString";
	const std::string expected_hash = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";
	Hasher::SHA256 sha256;
	FIFO hash;
	const auto ok = sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), hash);
	ASSERT_TRUE(fn_name, ok);
	ASSERT_EQUAL(fn_name, expected_hash, DeserializeString(hash.Data()));
	RETURN_TEST(fn_name, 0);
}

int test_sha256_hash_byte_input_ranges() {
	const std::string fn_name = "test_sha256_hash_byte_input_ranges";
	const std::string expected_hash = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";
	const std::string_view string_input = "HashThisString";
	const std::vector<std::uint8_t> vector_input(string_input.begin(), string_input.end());
	const std::array<std::byte, 14> array_input {
		std::byte{'H'}, std::byte{'a'}, std::byte{'s'}, std::byte{'h'},
		std::byte{'T'}, std::byte{'h'}, std::byte{'i'}, std::byte{'s'},
		std::byte{'S'}, std::byte{'t'}, std::byte{'r'}, std::byte{'i'},
		std::byte{'n'}, std::byte{'g'}
	};
	Hasher::SHA256 sha256;

	FIFO string_hash;
	ASSERT_TRUE(fn_name, sha256.Hash(string_input, string_hash));
	ASSERT_EQUAL(fn_name, expected_hash, DeserializeString(string_hash.Data()));

	FIFO vector_hash;
	ASSERT_TRUE(fn_name, sha256.Hash(vector_input, vector_hash));
	ASSERT_EQUAL(fn_name, expected_hash, DeserializeString(vector_hash.Data()));

	FIFO span_hash;
	ASSERT_TRUE(fn_name, sha256.Hash(std::span<const std::uint8_t>(vector_input), span_hash));
	ASSERT_EQUAL(fn_name, expected_hash, DeserializeString(span_hash.Data()));

	FIFO byte_span_hash;
	ASSERT_TRUE(fn_name, sha256.Hash(std::span<const std::byte>(array_input), byte_span_hash));
	ASSERT_EQUAL(fn_name, expected_hash, DeserializeString(byte_span_hash.Data()));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Distinct inputs
// -------------------

int test_sha256_collision_resistance() {
	const std::string fn_name = "test_sha256_collision_resistance";
	const std::string input_data_1 = "Original Input Data";
	const std::string input_data_2 = "Original Input Data!";
	Hasher::SHA256 sha256;
	FIFO hash_1_fifo;
	ASSERT_TRUE(fn_name, sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_1.data()), input_data_1.size()), hash_1_fifo));
	FIFO hash_2_fifo;
	ASSERT_TRUE(fn_name, sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_2.data()), input_data_2.size()), hash_2_fifo));
	ASSERT_NOT_EQUAL(fn_name, DeserializeString(hash_1_fifo.Data()), DeserializeString(hash_2_fifo.Data()));
	RETURN_TEST(fn_name, 0);
}

int test_sha256_produces_different_content() {
	const std::string fn_name = "test_sha256_produces_different_content";
	const std::string original_data = "Data to hash";
	Hasher::SHA256 sha256;
	FIFO hash_fifo;
	ASSERT_TRUE(fn_name, sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), hash_fifo));
	ASSERT_NOT_EQUAL(fn_name, original_data, DeserializeString(hash_fifo.Data()));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Stream
// -------------------

int test_sha256_hash_using_consumer_producer() {
	const std::string fn_name = "test_sha256_hash_using_consumer_producer";
	const std::string input_data = "HashThisString";
	const std::string expected_hash = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";
	Hasher::SHA256 sha256;
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	auto hash_consumer = sha256.Hash(producer.Consumer());
	ASSERT_TRUE(fn_name, hash_consumer.IsWritable() || !hash_consumer.Empty());
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(fn_name, hash_result.Empty());
	ASSERT_EQUAL(fn_name, expected_hash, DeserializeString(hash_result));
	RETURN_TEST(fn_name, 0);
}

int test_sha256_stream_and_block_equality() {
	const std::string fn_name = "test_sha256_stream_and_block_equality";
	const std::string input_data = "Data to hash for stream and block equality test";
	Hasher::SHA256 sha256;
	FIFO block_hash_fifo;
	ASSERT_TRUE(fn_name, sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), block_hash_fifo));
	const std::string block_hash = DeserializeString(block_hash_fifo.Data());
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	auto stream_hash_consumer = sha256.Hash(producer.Consumer());
	ASSERT_TRUE(fn_name, stream_hash_consumer.IsWritable() || !stream_hash_consumer.Empty());
	auto stream_hash_result = ReadAllFromConsumer(stream_hash_consumer);
	ASSERT_FALSE(fn_name, stream_hash_result.Empty());
	ASSERT_EQUAL(fn_name, block_hash, DeserializeString(stream_hash_result));
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Correctness
	// -------------------
	result += test_sha256_hash_correctness();
	result += test_sha256_hash_byte_input_ranges();

	// -------------------
	// Distinct inputs
	// -------------------
	result += test_sha256_collision_resistance();
	result += test_sha256_produces_different_content();

	// -------------------
	// Stream
	// -------------------
	result += test_sha256_hash_using_consumer_producer();
	result += test_sha256_stream_and_block_equality();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
