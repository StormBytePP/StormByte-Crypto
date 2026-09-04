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

#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/string.hxx>
#include <StormByte/test_handlers.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
using namespace StormByte::Crypto;
namespace fs = std::filesystem;
#ifndef STORMBYTE_TEST_KEYS_DIR
#error "STORMBYTE_TEST_KEYS_DIR must be defined by CMake"
#endif
static fs::path KeysDir() {
	const fs::path dir{STORMBYTE_TEST_KEYS_DIR};
	fs::create_directories(dir);
	return dir;
}
#ifdef STORMBYTE_TEST_KEYS_PASSWORD
static Password TestKeysPassword() {
	return Password(STORMBYTE_TEST_KEYS_PASSWORD);
}
#else
static Password TestKeysPassword() {
	return Password("StormByteTestPassphrase!");
}
#endif
// ---------------------------------------------------------------------------
// Garbage / invalid key material: Load must reject, never succeed
// ---------------------------------------------------------------------------
int TestLoadEmptyFileFails() {
	const std::string fn_name = "TestLoadEmptyFileFails";
	const auto path = KeysDir() / "empty.pem";
	{
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(fn_name, static_cast<bool>(ofs));
	}
	ASSERT_FALSE(fn_name, KeyPair::Load(path));
	ASSERT_FALSE(fn_name, KeyPair::Load(path, path));
	RETURN_TEST(fn_name, 0);
}
int TestLoadRandomGarbageFails() {
	const std::string fn_name = "TestLoadRandomGarbageFails";
	const auto path = KeysDir() / "garbage.bin";
	{
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		const char junk[] = "this-is-not-a-key\x00\x01\x02\xff";
		ofs.write(junk, static_cast<std::streamsize>(sizeof(junk) - 1));
		ASSERT_TRUE(fn_name, static_cast<bool>(ofs));
	}
	ASSERT_FALSE(fn_name, KeyPair::Load(path));
	RETURN_TEST(fn_name, 0);
}
int TestLoadMalformedPemHeaderFails() {
	const std::string fn_name = "TestLoadMalformedPemHeaderFails";
	const auto path = KeysDir() / "bad_pem.pem";
	{
		std::ofstream ofs(path);
		ofs << "-----BEGIN NOT A KEY-----\n"
			<< "YWJjZGVmZ2hpams=\n"
			<< "-----END NOT A KEY-----\n";
		ASSERT_TRUE(fn_name, static_cast<bool>(ofs));
	}
	ASSERT_FALSE(fn_name, KeyPair::Load(path));
	RETURN_TEST(fn_name, 0);
}
int TestLoadPemMissingEndFails() {
	const std::string fn_name = "TestLoadPemMissingEndFails";
	const auto path = KeysDir() / "pem_no_end.pem";
	{
		std::ofstream ofs(path);
		ofs << "-----BEGIN PRIVATE KEY-----\n"
			<< "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n";
		ASSERT_TRUE(fn_name, static_cast<bool>(ofs));
	}
	ASSERT_FALSE(fn_name, KeyPair::Load(path));
	RETURN_TEST(fn_name, 0);
}
int TestLoadPemInvalidBase64Fails() {
	const std::string fn_name = "TestLoadPemInvalidBase64Fails";
	const auto path = KeysDir() / "pem_bad_b64.pem";
	{
		std::ofstream ofs(path);
		ofs << "-----BEGIN PRIVATE KEY-----\n"
			<< "@@@@not-valid-base64@@@@\n"
			<< "-----END PRIVATE KEY-----\n";
		ASSERT_TRUE(fn_name, static_cast<bool>(ofs));
	}
	ASSERT_FALSE(fn_name, KeyPair::Load(path));
	RETURN_TEST(fn_name, 0);
}
int TestLoadNonexistentPathFails() {
	const std::string fn_name = "TestLoadNonexistentPathFails";
	const auto path = KeysDir() / "no_such_file.pem";
	ASSERT_FALSE(fn_name, fs::exists(path));
	ASSERT_FALSE(fn_name, KeyPair::Load(path));
	ASSERT_FALSE(fn_name, KeyPair::Load(path, path));
	RETURN_TEST(fn_name, 0);
}
int TestLoadDirectoryAsPathFails() {
	const std::string fn_name = "TestLoadDirectoryAsPathFails";
	const auto dir = KeysDir() / "as_dir";
	fs::create_directories(dir);
	ASSERT_FALSE(fn_name, KeyPair::Load(dir));
	RETURN_TEST(fn_name, 0);
}
int TestLoadTruncatedDerFails() {
	const std::string fn_name = "TestLoadTruncatedDerFails";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp);
	const auto out = KeysDir() / "trunc_der";
	fs::create_directories(out);
	ASSERT_TRUE(fn_name, kp->Save(out, "rsa", KeyPair::StorageFormat::DER));
	const auto privPath = out / "rsa.der";
	std::vector<char> bytes;
	{
		std::ifstream ifs(privPath, std::ios::binary);
		bytes.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
	}
	ASSERT_FALSE(fn_name, bytes.empty());
	// Too short for any complete ASN.1 private key; must not Load
	bytes.resize(std::min<size_t>(bytes.size(), 8));
	const auto truncPath = out / "rsa_trunc.der";
	{
		std::ofstream ofs(truncPath, std::ios::binary | std::ios::trunc);
		ofs.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
		ASSERT_TRUE(fn_name, static_cast<bool>(ofs));
	}
	ASSERT_FALSE(fn_name, KeyPair::Load(truncPath));
	ASSERT_FALSE(fn_name, KeyPair::Load(out / "rsa.pub.der", truncPath));
	RETURN_TEST(fn_name, 0);
}
int TestLoadMismatchedRsaPubDsaPrivFails() {
	const std::string fn_name = "TestLoadMismatchedRsaPubDsaPrivFails";
	auto rsa = KeyPair::RSA::Generate(2048);
	auto dsa = KeyPair::DSA::Generate(2048);
	ASSERT_TRUE(fn_name, rsa);
	ASSERT_TRUE(fn_name, dsa);
	const auto out = KeysDir() / "mismatch_rsa_dsa";
	fs::create_directories(out);
	ASSERT_TRUE(fn_name, rsa->SavePublic(out / "rsa.pub.pem"));
	ASSERT_TRUE(fn_name, dsa->SavePrivate(out / "dsa.pem"));
	ASSERT_FALSE(fn_name, KeyPair::Load(out / "rsa.pub.pem", out / "dsa.pem"));
	RETURN_TEST(fn_name, 0);
}
int TestLoadEncryptedWithoutPasswordFails() {
	const std::string fn_name = "TestLoadEncryptedWithoutPasswordFails";
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp);
	const auto out = KeysDir() / "enc_no_pass";
	fs::create_directories(out);
	ASSERT_TRUE(fn_name, kp->Save(out, "rsa", TestKeysPassword()));
	ASSERT_FALSE(fn_name, KeyPair::Load(out / "rsa.pub.pem", out / "rsa.pem"));
	ASSERT_FALSE(fn_name, KeyPair::Load(out / "rsa.pem"));
	RETURN_TEST(fn_name, 0);
}
int main() {
	fs::remove_all(KeysDir());
	fs::create_directories(KeysDir());
	int result = 0;
	result += TestLoadEmptyFileFails();
	result += TestLoadRandomGarbageFails();
	result += TestLoadMalformedPemHeaderFails();
	result += TestLoadPemMissingEndFails();
	result += TestLoadPemInvalidBase64Fails();
	result += TestLoadNonexistentPathFails();
	result += TestLoadDirectoryAsPathFails();
	result += TestLoadTruncatedDerFails();
	result += TestLoadMismatchedRsaPubDsaPrivFails();
	result += TestLoadEncryptedWithoutPasswordFails();
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
