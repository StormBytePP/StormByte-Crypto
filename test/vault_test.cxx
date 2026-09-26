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

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/vault.hxx>
#include <StormByte/test_handlers.h>
#include <iostream>
#include <utility>
using namespace StormByte::Crypto;
int TestVaultEmptyOnConstruct() {
	const std::string fn_name = "TestVaultEmptyOnConstruct";
	Vault vault;
	ASSERT_TRUE(fn_name, vault.Empty());
	ASSERT_EQUAL(fn_name, vault.Size(), static_cast<std::size_t>(0));
	ASSERT_FALSE(fn_name, vault.Contains("anything"));
	RETURN_TEST(fn_name, 0);
}

int TestVaultStoreAndGet() {
	const std::string fn_name = "TestVaultStoreAndGet";
	Vault vault;
	vault.Store("db", Password("s3cret"));
	vault.Store("api", Password("token-xyz"));
	ASSERT_FALSE(fn_name, vault.Empty());
	ASSERT_EQUAL(fn_name, vault.Size(), static_cast<std::size_t>(2));
	ASSERT_TRUE(fn_name, vault.Contains("db"));
	ASSERT_TRUE(fn_name, vault.Contains("api"));
	auto db = vault.Get("db");
	ASSERT_TRUE(fn_name, static_cast<bool>(db));
	ASSERT_TRUE(fn_name, *db == Password("s3cret"));
	auto api = vault.Get("api");
	ASSERT_TRUE(fn_name, static_cast<bool>(api));
	ASSERT_TRUE(fn_name, *api == Password("token-xyz"));
	RETURN_TEST(fn_name, 0);
}

int TestVaultGetMissing() {
	const std::string fn_name = "TestVaultGetMissing";
	Vault vault;
	vault.Store("only", Password("present"));
	auto missing = vault.Get("nope");
	ASSERT_FALSE(fn_name, static_cast<bool>(missing));
	const std::string message = missing.error()->what();
	ASSERT_TRUE(fn_name, message.find("StormByte::Crypto::Vault") != std::string::npos);
	RETURN_TEST(fn_name, 0);
}

int TestVaultOverwrite() {
	const std::string fn_name = "TestVaultOverwrite";
	Vault vault;
	vault.Store("key", Password("first"));
	vault.Store("key", Password("second"));
	ASSERT_EQUAL(fn_name, vault.Size(), static_cast<std::size_t>(1));
	auto pwd = vault.Get("key");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_TRUE(fn_name, *pwd == Password("second"));
	RETURN_TEST(fn_name, 0);
}

int TestVaultRemove() {
	const std::string fn_name = "TestVaultRemove";
	Vault vault;
	vault.Store("a", Password("one"));
	vault.Store("b", Password("two"));
	vault.Remove("a");
	ASSERT_FALSE(fn_name, vault.Contains("a"));
	ASSERT_TRUE(fn_name, vault.Contains("b"));
	ASSERT_EQUAL(fn_name, vault.Size(), static_cast<std::size_t>(1));
	vault.Remove("does-not-exist");
	ASSERT_EQUAL(fn_name, vault.Size(), static_cast<std::size_t>(1));
	RETURN_TEST(fn_name, 0);
}

int TestVaultClear() {
	const std::string fn_name = "TestVaultClear";
	Vault vault;
	vault.Store("x", Password("aaa"));
	vault.Store("y", Password("bbb"));
	vault.Store("z", Password("ccc"));
	vault.Clear();
	ASSERT_TRUE(fn_name, vault.Empty());
	ASSERT_EQUAL(fn_name, vault.Size(), static_cast<std::size_t>(0));
	ASSERT_FALSE(fn_name, vault.Contains("x"));
	ASSERT_FALSE(fn_name, static_cast<bool>(vault.Get("y")));
	RETURN_TEST(fn_name, 0);
}

int TestVaultMoveConstruct() {
	const std::string fn_name = "TestVaultMoveConstruct";
	Vault original;
	original.Store("moved", Password("payload"));
	Vault moved(std::move(original));
	ASSERT_TRUE(fn_name, original.Empty());
	ASSERT_EQUAL(fn_name, original.Size(), static_cast<std::size_t>(0));
	ASSERT_FALSE(fn_name, moved.Empty());
	ASSERT_TRUE(fn_name, moved.Contains("moved"));
	auto pwd = moved.Get("moved");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_TRUE(fn_name, *pwd == Password("payload"));
	RETURN_TEST(fn_name, 0);
}

int TestVaultMoveAssign() {
	const std::string fn_name = "TestVaultMoveAssign";
	Vault src;
	src.Store("alpha", Password("111"));
	src.Store("beta", Password("222"));
	Vault dst;
	dst.Store("old", Password("should-be-wiped"));
	dst = std::move(src);
	ASSERT_TRUE(fn_name, src.Empty());
	ASSERT_EQUAL(fn_name, dst.Size(), static_cast<std::size_t>(2));
	ASSERT_TRUE(fn_name, dst.Contains("alpha"));
	ASSERT_TRUE(fn_name, dst.Contains("beta"));
	ASSERT_FALSE(fn_name, dst.Contains("old"));
	auto alpha = dst.Get("alpha");
	ASSERT_TRUE(fn_name, static_cast<bool>(alpha));
	ASSERT_TRUE(fn_name, *alpha == Password("111"));
	RETURN_TEST(fn_name, 0);
}

int TestVaultPasswordSharedOwnership() {
	const std::string fn_name = "TestVaultPasswordSharedOwnership";
	Password shared("shared-secret");
	Vault vault;
	vault.Store("ref1", shared);
	vault.Store("ref2", shared);
	auto a = vault.Get("ref1");
	auto b = vault.Get("ref2");
	ASSERT_TRUE(fn_name, static_cast<bool>(a));
	ASSERT_TRUE(fn_name, static_cast<bool>(b));
	ASSERT_TRUE(fn_name, *a == Password("shared-secret"));
	ASSERT_TRUE(fn_name, *b == Password("shared-secret"));
	ASSERT_TRUE(fn_name, *a == *b);
	ASSERT_TRUE(fn_name, shared == Password("shared-secret"));
	RETURN_TEST(fn_name, 0);
}

int TestVaultStoreFromConstChar() {
	const std::string fn_name = "TestVaultStoreFromConstChar";
	Vault vault;
	vault.Store("implicit", Password("from-literal"));
	auto pwd = vault.Get("implicit");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_FALSE(fn_name, pwd->Empty());
	ASSERT_TRUE(fn_name, *pwd == Password("from-literal"));
	ASSERT_EQUAL(fn_name, pwd->Size(), static_cast<std::size_t>(12));
	RETURN_TEST(fn_name, 0);
}

int TestVaultPasswordBoolConversion() {
	const std::string fn_name = "TestVaultPasswordBoolConversion";
	Password p("non-empty");
	ASSERT_TRUE(fn_name, static_cast<bool>(p));
	ASSERT_FALSE(fn_name, p.Empty());
	RETURN_TEST(fn_name, 0);
}

int TestVaultReStoreAfterClear() {
	const std::string fn_name = "TestVaultReStoreAfterClear";
	Vault vault;
	vault.Store("tmp", Password("gone"));
	vault.Clear();
	vault.Store("tmp", Password("back"));
	auto pwd = vault.Get("tmp");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_TRUE(fn_name, *pwd == Password("back"));
	ASSERT_EQUAL(fn_name, vault.Size(), static_cast<std::size_t>(1));
	RETURN_TEST(fn_name, 0);
}

int TestVaultPasswordOperatorEqual() {
	const std::string fn_name = "TestVaultPasswordOperatorEqual";
	Password a("same");
	Password b("same");
	Password c("other");
	ASSERT_TRUE(fn_name, a == b);
	ASSERT_FALSE(fn_name, a != b);
	ASSERT_FALSE(fn_name, a == c);
	ASSERT_TRUE(fn_name, a != c);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;
	result += TestVaultEmptyOnConstruct();
	result += TestVaultStoreAndGet();
	result += TestVaultGetMissing();
	result += TestVaultOverwrite();
	result += TestVaultRemove();
	result += TestVaultClear();
	result += TestVaultMoveConstruct();
	result += TestVaultMoveAssign();
	result += TestVaultPasswordSharedOwnership();
	result += TestVaultStoreFromConstChar();
	result += TestVaultPasswordBoolConversion();
	result += TestVaultReStoreAfterClear();
	result += TestVaultPasswordOperatorEqual();
	if (result == 0) {
		std::cout << "All Vault tests passed!" << std::endl;
	} else {
		std::cout << result << " Vault tests failed." << std::endl;
	}

	return result;
}
