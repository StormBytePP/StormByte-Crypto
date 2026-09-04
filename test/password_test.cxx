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

#include <StormByte/crypto/password.hxx>
#include <StormByte/test_handlers.h>
#include <string>
#include <utility>
using namespace StormByte::Crypto;
int TestPasswordConstructFromCString() {
	const std::string fn_name = "TestPasswordConstructFromCString";
	Password p("secret-value");
	ASSERT_FALSE(fn_name, p.Empty());
	ASSERT_TRUE(fn_name, p.Size() > 0);
	ASSERT_TRUE(fn_name, static_cast<bool>(p));
	RETURN_TEST(fn_name, 0);
}
int TestPasswordConstructFromString() {
	const std::string fn_name = "TestPasswordConstructFromString";
	std::string raw = "from-std-string";
	Password p(std::move(raw));
	ASSERT_FALSE(fn_name, p.Empty());
	ASSERT_EQUAL(fn_name, p.Size(), std::string("from-std-string").size());
	RETURN_TEST(fn_name, 0);
}
int TestPasswordConstructFromBytes() {
	const std::string fn_name = "TestPasswordConstructFromBytes";
	const unsigned char bytes[] = { 0x01, 0x02, 0x03, 0x04, 0xff };
	Password p(bytes, sizeof(bytes));
	ASSERT_FALSE(fn_name, p.Empty());
	ASSERT_EQUAL(fn_name, p.Size(), sizeof(bytes));
	RETURN_TEST(fn_name, 0);
}
int TestPasswordEmpty() {
	const std::string fn_name = "TestPasswordEmpty";
	Password empty(static_cast<const void*>(nullptr), 0);
	ASSERT_TRUE(fn_name, empty.Empty());
	ASSERT_EQUAL(fn_name, empty.Size(), static_cast<std::size_t>(0));
	ASSERT_FALSE(fn_name, static_cast<bool>(empty));
	Password nonempty("x");
	ASSERT_FALSE(fn_name, nonempty.Empty());
	ASSERT_TRUE(fn_name, static_cast<bool>(nonempty));
	RETURN_TEST(fn_name, 0);
}
int TestPasswordEqualitySameContent() {
	const std::string fn_name = "TestPasswordEqualitySameContent";
	Password a("same-secret");
	Password b("same-secret");
	ASSERT_TRUE(fn_name, a == b);
	ASSERT_FALSE(fn_name, a != b);
	RETURN_TEST(fn_name, 0);
}
int TestPasswordEqualityDifferentContent() {
	const std::string fn_name = "TestPasswordEqualityDifferentContent";
	Password a("alpha");
	Password b("beta");
	ASSERT_FALSE(fn_name, a == b);
	ASSERT_TRUE(fn_name, a != b);
	RETURN_TEST(fn_name, 0);
}
int TestPasswordSelfEquality() {
	const std::string fn_name = "TestPasswordSelfEquality";
	Password p("self");
	ASSERT_TRUE(fn_name, p == p);
	ASSERT_FALSE(fn_name, p != p);
	RETURN_TEST(fn_name, 0);
}
int TestPasswordCopySharesContent() {
	const std::string fn_name = "TestPasswordCopySharesContent";
	Password original("shared-bytes");
	Password copy(original);
	ASSERT_TRUE(fn_name, original == copy);
	ASSERT_EQUAL(fn_name, original.Size(), copy.Size());
	ASSERT_FALSE(fn_name, original.Empty());
	ASSERT_FALSE(fn_name, copy.Empty());
	RETURN_TEST(fn_name, 0);
}
int TestPasswordMoveLeavesUsableSource() {
	const std::string fn_name = "TestPasswordMoveLeavesUsableSource";
	Password source("move-me");
	Password dest(std::move(source));
	ASSERT_FALSE(fn_name, dest.Empty());
	ASSERT_TRUE(fn_name, dest.Size() > 0);
	// After move, source must remain safe to query (empty or still valid; no crash).
	(void)source.Empty();
	(void)source.Size();
	RETURN_TEST(fn_name, 0);
}
int TestPasswordBinaryNotEqualToTextOfSameLength() {
	const std::string fn_name = "TestPasswordBinaryNotEqualToTextOfSameLength";
	const unsigned char bin[] = { 'a', 'b', 'c', 0x00 };
	Password fromBytes(bin, sizeof(bin));
	Password fromText("abc");
	// Different size (4 vs 3) or different content including trailing zero.
	ASSERT_FALSE(fn_name, fromBytes == fromText);
	RETURN_TEST(fn_name, 0);
}
int main() {
	int result = 0;
	result += TestPasswordConstructFromCString();
	result += TestPasswordConstructFromString();
	result += TestPasswordConstructFromBytes();
	result += TestPasswordEmpty();
	result += TestPasswordEqualitySameContent();
	result += TestPasswordEqualityDifferentContent();
	result += TestPasswordSelfEquality();
	result += TestPasswordCopySharesContent();
	result += TestPasswordMoveLeavesUsableSource();
	result += TestPasswordBinaryNotEqualToTextOfSameLength();
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
