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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <vector>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Round trip
// -------------------

int test_bzip2_compression_decompression_integrity() {
	const std::string fn_name = "test_bzip2_compression_decompression_integrity";
	const std::string input_data = "OriginalDataForIntegrityCheck";
	Compressor::Bzip2 bzip2;
	FIFO compressed_data;
	ASSERT_TRUE(fn_name, bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), input_data.size()), compressed_data));
	ASSERT_FALSE(fn_name, compressed_data.Empty());
	FIFO decompressed_data;
	ASSERT_TRUE(fn_name, bzip2.Decompress(compressed_data, decompressed_data));
	ASSERT_FALSE(fn_name, decompressed_data.Empty());
	ASSERT_EQUAL(fn_name, DeserializeString(decompressed_data.Data()), input_data);
	RETURN_TEST(fn_name, 0);
}

int test_bzip2_compression_produces_different_content() {
	const std::string fn_name = "test_bzip2_compression_produces_different_content";
	const std::string original_data = "Compress this data";
	Compressor::Bzip2 bzip2;
	FIFO compressed_data;
	ASSERT_TRUE(fn_name, bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), compressed_data));
	ASSERT_FALSE(fn_name, compressed_data.Empty());
	const std::string compressed_string = DeserializeString(compressed_data.Data());
	ASSERT_FALSE(fn_name, compressed_string.empty());
	ASSERT_NOT_EQUAL(fn_name, compressed_string, original_data);
	RETURN_TEST(fn_name, 0);
}

int test_bzip2_buffer_path() {
	const std::string fn_name = "test_bzip2_buffer_path";
	std::string src(1024, 'B');
	FIFO input;
	std::vector<std::byte> bytes(src.size());
	std::transform(src.begin(), src.end(), bytes.begin(),
		[](char c) { return static_cast<std::byte>(c); });
	input.Write(bytes);
	Compressor::Bzip2 bzip2;
	FIFO compressed;
	ASSERT_TRUE(fn_name, bzip2.Compress(input, compressed));
	FIFO decompressed;
	ASSERT_TRUE(fn_name, bzip2.Decompress(compressed, decompressed));
	ASSERT_EQUAL(fn_name, DeserializeString(decompressed.Data()), src);
	RETURN_TEST(fn_name, 0);
}

int test_bzip2_compress_level_bounds() {
	const std::string fn_name = "test_bzip2_compress_level_bounds";
	const std::string input = "level-bounds-test-payload";
	for (unsigned short level : {1, 5, 9}) {
		Compressor::Bzip2 bzip2(level);
		FIFO compressed;
		ASSERT_TRUE(fn_name, bzip2.Compress(std::span<const std::byte>(
			reinterpret_cast<const std::byte*>(input.data()), input.size()), compressed));
		FIFO decompressed;
		ASSERT_TRUE(fn_name, bzip2.Decompress(compressed, decompressed));
		ASSERT_EQUAL(fn_name, DeserializeString(decompressed.Data()), input);
	}
	RETURN_TEST(fn_name, 0);
}

int test_bzip2_empty_input() {
	const std::string fn_name = "test_bzip2_empty_input";
	Compressor::Bzip2 bzip2;
	FIFO compressed;
	ASSERT_TRUE(fn_name, bzip2.Compress(std::span<const std::byte>(), compressed));
	ASSERT_TRUE(fn_name, compressed.Empty());
	FIFO decompressed;
	ASSERT_TRUE(fn_name, bzip2.Decompress(std::span<const std::byte>(), decompressed));
	ASSERT_TRUE(fn_name, decompressed.Empty());
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Corruption
// -------------------

int test_bzip2_decompress_corrupted_data() {
	const std::string fn_name = "test_bzip2_decompress_corrupted_data";
	const std::string original_data = "This is some valid data to compress and corrupt.";
	Compressor::Bzip2 bzip2;
	FIFO compressed_data;
	ASSERT_TRUE(fn_name, bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), compressed_data));
	ASSERT_FALSE(fn_name, compressed_data.Empty());
	std::string corrupted_string = DeserializeString(compressed_data.Data());
	ASSERT_FALSE(fn_name, corrupted_string.empty());
	if (corrupted_string.size() > 10) {
		corrupted_string[4] ^= static_cast<char>(0xFF);
		corrupted_string[corrupted_string.size() / 2] ^= static_cast<char>(0xFF);
		corrupted_string[corrupted_string.size() - 3] ^= static_cast<char>(0xFF);
	} else if (!corrupted_string.empty()) {
		corrupted_string[0] ^= static_cast<char>(0xFF);
	}
	FIFO bad_decompress;
	const bool ok = bzip2.Decompress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), bad_decompress);
	if (ok)
		ASSERT_NOT_EQUAL(fn_name, DeserializeString(bad_decompress.Data()), original_data);
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Stream
// -------------------

int test_bzip2_compress_decompress_using_consumer_producer() {
	const std::string fn_name = "test_bzip2_compress_decompress_using_consumer_producer";
	const std::string input_data = "This is some data to compress using the Consumer/Producer model.";
	Compressor::Bzip2 bzip2;
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	auto compressed_consumer = bzip2.Compress(producer.Consumer());
	ASSERT_TRUE(fn_name, compressed_consumer.IsWritable() || !compressed_consumer.Empty());
	auto decompressed_consumer = bzip2.Decompress(compressed_consumer);
	ASSERT_TRUE(fn_name, decompressed_consumer.IsWritable() || !decompressed_consumer.Empty());
	FIFO decompressed_data = ReadAllFromConsumer(decompressed_consumer);
	ASSERT_FALSE(fn_name, decompressed_data.Empty());
	ASSERT_EQUAL(fn_name, input_data, DeserializeString(decompressed_data));
	RETURN_TEST(fn_name, 0);
}

int test_bzip2_streaming_decompress() {
	const std::string fn_name = "test_bzip2_streaming_decompress";
	std::string big(128 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));
	Compressor::Bzip2 bzip2;
	FIFO compressedFifo;
	ASSERT_TRUE(fn_name, bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(big.data()), big.size()), compressedFifo));
	ASSERT_FALSE(fn_name, compressedFifo.Empty());
	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const auto& raw = compressedFifo.Data();
	const size_t rawSize = raw.size();
	const size_t chunk = 4096;
	for (size_t off = 0; off < rawSize; off += chunk) {
		const size_t n = std::min(chunk, rawSize - off);
		std::vector<std::byte> bytes(raw.begin() + static_cast<std::ptrdiff_t>(off),
			raw.begin() + static_cast<std::ptrdiff_t>(off + n));
		(void)producer.Write(bytes);
	}
	producer.Close();
	auto decompressedFifo = ReadAllFromConsumer(bzip2.Decompress(consumerIn));
	ASSERT_EQUAL(fn_name, DeserializeString(decompressedFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int test_bzip2_streaming_round_trip() {
	const std::string fn_name = "test_bzip2_streaming_round_trip";
	std::string big(64 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('a' + (i % 26));
	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const size_t chunk = 2048;
	for (size_t off = 0; off < big.size(); off += chunk) {
		const size_t n = std::min(chunk, big.size() - off);
		std::vector<std::byte> bytes(n);
		std::transform(big.begin() + static_cast<std::ptrdiff_t>(off),
			big.begin() + static_cast<std::ptrdiff_t>(off + n),
			bytes.begin(),
			[](char c) { return static_cast<std::byte>(c); });
		(void)producer.Write(bytes);
	}
	producer.Close();
	Compressor::Bzip2 bzip2;
	auto outFifo = ReadAllFromConsumer(bzip2.Decompress(bzip2.Compress(consumerIn)));
	ASSERT_EQUAL(fn_name, DeserializeString(outFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Round trip
	// -------------------
	result += test_bzip2_compression_decompression_integrity();
	result += test_bzip2_compression_produces_different_content();
	result += test_bzip2_buffer_path();
	result += test_bzip2_compress_level_bounds();
	result += test_bzip2_empty_input();

	// -------------------
	// Corruption
	// -------------------
	result += test_bzip2_decompress_corrupted_data();

	// -------------------
	// Stream
	// -------------------
	result += test_bzip2_compress_decompress_using_consumer_producer();
	result += test_bzip2_streaming_decompress();
	result += test_bzip2_streaming_round_trip();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
