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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"
#include <thread>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
constexpr const unsigned short curve_bits = 256;
int TestECCEncryptDecrypt() {
	const std::string fn_name = "TestECCEncryptDecrypt";
	const std::string message = "This is a test message.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());
	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}

int TestECCDecryptionWithCorruptedData() {
	const std::string fn_name = "TestECCDecryptionWithCorruptedData";
	const std::string message = "Important message!";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	auto corrupted_string = encrypted_string;
	if (!corrupted_string.empty()) {
		corrupted_string[0] = ~corrupted_string[0];
	}

	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

int TestECCDecryptWithMismatchedKey() {
	const std::string fn_name = "TestECCDecryptWithMismatchedKey";
	const std::string message = "Sensitive message.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	auto keypair_result_2 = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result_2);
	Crypter::ECC ecc2(keypair_result_2);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	FIFO decrypted_data;
	auto decrypt_result = ecc2.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

int TestECCWithCorruptedKeys() {
	const std::string fn_name = "TestECCWithCorruptedKeys";
	const std::string message = "This is a test message.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	std::string corrupted_public_key = keypair_result->PublicKey();
	if (!corrupted_public_key.empty())
		corrupted_public_key[0] = static_cast<char>(~corrupted_public_key[0]);
	auto badKp = std::make_shared<KeyPair::ECC>(
		std::move(corrupted_public_key),
		Password("not-a-valid-ecc-private-key")
	);
	Crypter::ECC ecc(badKp);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data
	);
	ASSERT_FALSE(fn_name, encrypt_result);
	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptionProducesDifferentContent() {
	const std::string fn_name = "TestECCEncryptionProducesDifferentContent";
	const std::string original_data = "ECC test message";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_NOT_EQUAL(fn_name, original_data, encrypted_string);
	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptDecryptUsingConsumerProducer() {
	const std::string fn_name = "TestECCEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	auto encrypted_consumer = ecc.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = ecc.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	StormByte::Buffer::FIFO decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty());
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

// =========================================================================
// Hybrid (Envelope) tests
// =========================================================================
int TestECCEncryptDecryptHybrid() {
	const std::string fn_name = "TestECCEncryptDecryptHybrid";
	const std::string message = "This is a hybrid envelope test message for ECC.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Hybrid
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	ASSERT_FALSE(fn_name, encrypted_data.Empty());
	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(
		std::span<const std::byte>(encrypted_data.Data().data(), encrypted_data.Data().size()),
		decrypted_data
	);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());
	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptDecryptHybridStreaming() {
	const std::string fn_name = "TestECCEncryptDecryptHybridStreaming";
	const std::string input_data = "This is some data to encrypt using Hybrid envelope with Consumer/Producer model.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	auto encrypted_consumer = ecc.Encrypt(consumer, Crypter::Asymmetric::Strategy::Hybrid);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = ecc.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	StormByte::Buffer::FIFO decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty());
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

int TestECCHybridVsNativeDifferentOutput() {
	const std::string fn_name = "TestECCHybridVsNativeDifferentOutput";
	const std::string message = "Same message for both modes";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO native_encrypted;
	auto native_ok = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		native_encrypted,
		Crypter::Asymmetric::Strategy::Native
	);
	ASSERT_TRUE(fn_name, native_ok);
	FIFO hybrid_encrypted;
	auto hybrid_ok = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		hybrid_encrypted,
		Crypter::Asymmetric::Strategy::Hybrid
	);
	ASSERT_TRUE(fn_name, hybrid_ok);
	ASSERT_NOT_EQUAL(fn_name,
		StormByte::String::FromByteVector(native_encrypted.Data()),
		StormByte::String::FromByteVector(hybrid_encrypted.Data())
	);
	RETURN_TEST(fn_name, 0);
}

// =========================================================================
// Explicit Native + auto-detect
// =========================================================================
int TestECCEncryptDecryptNativeExplicit() {
	const std::string fn_name = "TestECCEncryptDecryptNativeExplicit";
	const std::string message = "Explicit Native strategy round-trip for ECC.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Native
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	ASSERT_FALSE(fn_name, encrypted_data.Empty());
	// Decrypt without strategy → auto-detect (Hybrid fails, Native succeeds)
	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(
		std::span<const std::byte>(encrypted_data.Data().data(), encrypted_data.Data().size()),
		decrypted_data
	);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());
	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}

int TestECCEncryptDecryptNativeExplicitStreaming() {
	const std::string fn_name = "TestECCEncryptDecryptNativeExplicitStreaming";
	const std::string input_data = "Native explicit streaming with auto-detect decrypt.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	auto encrypted_consumer = ecc.Encrypt(consumer, Crypter::Asymmetric::Strategy::Native);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = ecc.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	StormByte::Buffer::FIFO decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty());
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

// =========================================================================
// Corruption / mismatch edge cases for auto-detect
// =========================================================================
int TestECCCorruptedHybridEnvelopeFails() {
	const std::string fn_name = "TestECCCorruptedHybridEnvelopeFails";
	const std::string message = "Hybrid envelope that will be corrupted.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Hybrid
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto corrupted = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, corrupted.empty());
	// Flip several bytes across the envelope (header / ESK / payload / tag region)
	if (corrupted.size() > 8) {
		corrupted[0] = static_cast<char>(~corrupted[0]);
		corrupted[corrupted.size() / 3] = static_cast<char>(corrupted[corrupted.size() / 3] ^ 0x5A);
		corrupted[corrupted.size() - 1] = static_cast<char>(~corrupted[corrupted.size() - 1]);
	} else {
		corrupted[0] = static_cast<char>(~corrupted[0]);
	}

	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted.data()), corrupted.size()),
		decrypted_data
	);
	// Hybrid fails; Native fallback on a Hybrid blob must also fail
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

int TestECCCorruptedNativeFailsAutoDetect() {
	const std::string fn_name = "TestECCCorruptedNativeFailsAutoDetect";
	const std::string message = "Native ciphertext that will be corrupted.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Native
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto corrupted = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, corrupted.empty());
	if (!corrupted.empty()) {
		corrupted[0] = static_cast<char>(~corrupted[0]);
		if (corrupted.size() > 2) {
			corrupted[corrupted.size() / 2] = static_cast<char>(corrupted[corrupted.size() / 2] ^ 0xFF);
		}
	}

	FIFO decrypted_data;
	auto decrypt_result = ecc.Decrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted.data()), corrupted.size()),
		decrypted_data
	);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

int TestECCHybridDecryptWithMismatchedKey() {
	const std::string fn_name = "TestECCHybridDecryptWithMismatchedKey";
	const std::string message = "Hybrid ciphertext, wrong private key.";
	auto keypair_result = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result);
	Crypter::ECC ecc(keypair_result);
	auto keypair_result_2 = KeyPair::ECC::Generate(curve_bits);
	ASSERT_TRUE(fn_name, keypair_result_2);
	Crypter::ECC ecc2(keypair_result_2);
	FIFO encrypted_data;
	auto encrypt_result = ecc.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Hybrid
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	FIFO decrypted_data;
	auto decrypt_result = ecc2.Decrypt(
		std::span<const std::byte>(encrypted_data.Data().data(), encrypted_data.Data().size()),
		decrypted_data
	);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;
	result += TestECCEncryptDecrypt();
	result += TestECCDecryptionWithCorruptedData();
	result += TestECCDecryptWithMismatchedKey();
	result += TestECCWithCorruptedKeys();
	result += TestECCEncryptionProducesDifferentContent();
	result += TestECCEncryptDecryptUsingConsumerProducer();
	result += TestECCEncryptDecryptHybrid();
	result += TestECCEncryptDecryptHybridStreaming();
	result += TestECCHybridVsNativeDifferentOutput();
	result += TestECCEncryptDecryptNativeExplicit();
	result += TestECCEncryptDecryptNativeExplicitStreaming();
	result += TestECCCorruptedHybridEnvelopeFails();
	result += TestECCCorruptedNativeFailsAutoDetect();
	result += TestECCHybridDecryptWithMismatchedKey();
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}

	return result;
}
