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
#include <StormByte/crypto/compressor/zlib.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Round trip
// -------------------

int test_zlib_compress_decompress_string() {
	const std::string fn_name = "test_zlib_compress_decompress_string";
	const std::string input = "The quick brown fox jumps over the lazy dog.\n";
	Compressor::Zlib compressor;
	FIFO compressed_data;
	ASSERT_TRUE(fn_name, compressor.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input.data()), input.size()), compressed_data));
	ASSERT_FALSE(fn_name, compressed_data.Empty());
	FIFO decompressed_data;
	ASSERT_TRUE(fn_name, compressor.Decompress(compressed_data, decompressed_data));
	ASSERT_EQUAL(fn_name, DeserializeString(decompressed_data.Data()), input);
	RETURN_TEST(fn_name, 0);
}

int test_zlib_byte_input_ranges() {
	const std::string fn_name = "test_zlib_byte_input_ranges";
	const std::string_view input = "Byte input range compression";
	const std::vector<std::uint8_t> bytes(input.begin(), input.end());
	Compressor::Zlib compressor;
	FIFO compressed;
	ASSERT_TRUE(fn_name, compressor.Compress(input, compressed));
	FIFO decompressed;
	ASSERT_TRUE(fn_name, compressor.Decompress(compressed.Data(), decompressed));
	ASSERT_EQUAL(fn_name, DeserializeString(decompressed.Data()), input);
	FIFO span_compressed;
	ASSERT_TRUE(fn_name, compressor.Compress(std::span<const std::uint8_t>(bytes), span_compressed));
	FIFO span_decompressed;
	ASSERT_TRUE(fn_name, compressor.Decompress(std::span<const std::byte>(span_compressed.Data()), span_decompressed));
	ASSERT_EQUAL(fn_name, DeserializeString(span_decompressed.Data()), input);
	RETURN_TEST(fn_name, 0);
}

int test_zlib_compress_decompress_buffer() {
	const std::string fn_name = "test_zlib_compress_decompress_buffer";
	std::string src(1024, 'A');
	FIFO input;
	std::vector<std::byte> bytes(src.size());
	std::transform(src.begin(), src.end(), bytes.begin(), [](char c) { return static_cast<std::byte>(c); });
	input.Write(bytes);
	Compressor::Zlib compressor;
	FIFO compressed_data;
	ASSERT_TRUE(fn_name, compressor.Compress(input, compressed_data));
	FIFO decompressed_data;
	ASSERT_TRUE(fn_name, compressor.Decompress(compressed_data, decompressed_data));
	ASSERT_EQUAL(fn_name, DeserializeString(decompressed_data.Data()), src);
	RETURN_TEST(fn_name, 0);
}

int test_zlib_compress_level_bounds() {
	const std::string fn_name = "test_zlib_compress_level_bounds";
	const std::string input = "level-bounds-test-payload";
	for (unsigned short level : {1, 5, 9}) {
		Compressor::Zlib zlib(level);
		FIFO compressed;
		ASSERT_TRUE(fn_name, zlib.Compress(std::span<const std::byte>(
			reinterpret_cast<const std::byte*>(input.data()), input.size()), compressed));
		FIFO decompressed;
		ASSERT_TRUE(fn_name, zlib.Decompress(compressed, decompressed));
		ASSERT_EQUAL(fn_name, DeserializeString(decompressed.Data()), input);
	}
	RETURN_TEST(fn_name, 0);
}

int test_zlib_empty_input() {
	const std::string fn_name = "test_zlib_empty_input";
	Compressor::Zlib zlib;
	FIFO compressed;
	ASSERT_TRUE(fn_name, zlib.Compress(std::span<const std::byte>(), compressed));
	FIFO decompressed;
	ASSERT_TRUE(fn_name, zlib.Decompress(compressed, decompressed));
	ASSERT_TRUE(fn_name, decompressed.Empty() || DeserializeString(decompressed.Data()).empty());
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Stream
// -------------------

int test_zlib_streaming() {
	const std::string fn_name = "test_zlib_streaming";
	std::string big(256 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));
	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const size_t chunk = 8192;
	for (size_t off = 0; off < big.size(); off += chunk) {
		const size_t n = std::min(chunk, big.size() - off);
		std::vector<std::byte> bytes(n);
		std::transform(big.begin() + off, big.begin() + off + n, bytes.begin(),
			[](char c) { return static_cast<std::byte>(c); });
		(void)producer.Write(bytes);
	}
	producer.Close();
	Compressor::Zlib comp;
	auto compressedFifo = ReadAllFromConsumer(comp.Compress(consumerIn));
	Compressor::Zlib decomp;
	FIFO decompressedFifo;
	ASSERT_TRUE(fn_name, decomp.Decompress(compressedFifo, decompressedFifo));
	ASSERT_EQUAL(fn_name, DeserializeString(decompressedFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int test_zlib_streaming_decompress() {
	const std::string fn_name = "test_zlib_streaming_decompress";
	std::string big(128 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));
	Compressor::Zlib comp;
	FIFO compressedFifo;
	ASSERT_TRUE(fn_name, comp.Compress(std::span<const std::byte>(
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
	Compressor::Zlib decomp;
	auto decompressedFifo = ReadAllFromConsumer(decomp.Decompress(consumerIn));
	ASSERT_EQUAL(fn_name, DeserializeString(decompressedFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int test_zlib_streaming_round_trip() {
	const std::string fn_name = "test_zlib_streaming_round_trip";
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
	Compressor::Zlib zlib;
	auto outFifo = ReadAllFromConsumer(zlib.Decompress(zlib.Compress(consumerIn)));
	ASSERT_EQUAL(fn_name, DeserializeString(outFifo.Data()), big);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Round trip
	// -------------------
	result += test_zlib_compress_decompress_string();
	result += test_zlib_byte_input_ranges();
	result += test_zlib_compress_decompress_buffer();
	result += test_zlib_compress_level_bounds();
	result += test_zlib_empty_input();

	// -------------------
	// Stream
	// -------------------
	result += test_zlib_streaming();
	result += test_zlib_streaming_decompress();
	result += test_zlib_streaming_round_trip();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
