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
#include <StormByte/crypto/hasher/sha3_256.hxx>
#include <StormByte/crypto/hasher/sha3_512.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// SHA3-256
// -------------------

int test_sha3_256_hash() {
	const std::string fn_name = "test_sha3_256_hash";
	const std::string input = "The quick brown fox jumps over the lazy dog";
	const std::string expected = "69070DDA01975C8C120C3AADA1B282394E7F032FA9CF32F4CB2259A0897DFC04";
	Hasher::SHA3_256 hasher;
	FIFO result;
	ASSERT_TRUE(fn_name, hasher.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input.data()), input.size()), result));
	ASSERT_EQUAL(fn_name, expected, DeserializeString(result.Data()));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// SHA3-512
// -------------------

int test_sha3_512_hash() {
	const std::string fn_name = "test_sha3_512_hash";
	const std::string input = "The quick brown fox jumps over the lazy dog";
	const std::string expected =
		"01DEDD5DE4EF14642445BA5F5B97C15E47B9AD931326E4B0727CD94CEFC44FFF"
		"23F07BF543139939B49128CAF436DC1BDEE54FCB24023A08D9403F9B4BF0D450";
	Hasher::SHA3_512 hasher;
	FIFO result;
	ASSERT_TRUE(fn_name, hasher.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input.data()), input.size()), result));
	ASSERT_EQUAL(fn_name, expected, DeserializeString(result.Data()));
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// SHA3-256
	// -------------------
	result += test_sha3_256_hash();

	// -------------------
	// SHA3-512
	// -------------------
	result += test_sha3_512_hash();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
