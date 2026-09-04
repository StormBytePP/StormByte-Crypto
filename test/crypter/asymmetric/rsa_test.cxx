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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/test_handlers.h>
#include "helpers.hxx"
#include <thread>
using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
int TestRSAEncryptDecrypt(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecrypt";
	const std::string message = "This is a test message.";
	Crypter::RSA rsa(kp);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	FIFO decrypted_data;
	auto decrypt_result = rsa.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted_string.data()), encrypted_string.size()), decrypted_data);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());
	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}
int TestRSADecryptionWithCorruptedData(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSADecryptionWithCorruptedData";
	const std::string message = "Important message!";
	Crypter::RSA rsa(kp);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, encrypted_string.empty());
	auto corrupted_string = encrypted_string;
	if (!corrupted_string.empty()) {
		corrupted_string[0] = ~corrupted_string[0];
	}
	FIFO decrypted_data;
	auto decrypt_result = rsa.Decrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_string.data()), corrupted_string.size()), decrypted_data);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestRSADecryptWithMismatchedKey(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSADecryptWithMismatchedKey";
	const std::string message = "Sensitive message.";
	Crypter::RSA rsa(kp);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp2);
	Crypter::RSA rsa2(kp2);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	FIFO decrypted_data;
	auto decrypt_result = rsa2.Decrypt(
		std::span<const std::byte>(encrypted_data.Data().data(), encrypted_data.Data().size()),
		decrypted_data
	);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestRSAWithCorruptedKeys(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAWithCorruptedKeys";
	const std::string message = "This is a test message.";
	Crypter::RSA rsa(kp);
	std::string corrupted_public_key = kp->PublicKey();
	if (!corrupted_public_key.empty())
		corrupted_public_key[0] = static_cast<char>(~corrupted_public_key[0]);
	auto badKp = std::make_shared<KeyPair::RSA>(
		std::move(corrupted_public_key),
		Password("not-a-valid-rsa-private-key")
	);
	Crypter::RSA corrupted_rsa(badKp);
	FIFO encrypted_data;
	auto encrypt_result = corrupted_rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data
	);
	ASSERT_FALSE(fn_name, encrypt_result);
	FIFO encrypted_data_valid;
	auto encrypt_result_valid = rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data_valid
	);
	ASSERT_TRUE(fn_name, encrypt_result_valid);
	FIFO decrypted_data;
	auto decrypt_result = corrupted_rsa.Decrypt(
		std::span<const std::byte>(encrypted_data_valid.Data().data(), encrypted_data_valid.Data().size()),
		decrypted_data
	);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestRSAEncryptionProducesDifferentContent(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptionProducesDifferentContent";
	const std::string original_data = "Sensitive message";
	Crypter::RSA rsa(kp);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(std::span<const std::byte>(reinterpret_cast<const std::byte*>(original_data.data()), original_data.size()), encrypted_data);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto encrypted_string = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_NOT_EQUAL(fn_name, encrypted_string, original_data);
	RETURN_TEST(fn_name, 0);
}
int TestRSAEncryptDecryptUsingConsumerProducer(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecryptUsingConsumerProducer";
	const std::string input_data = "This is some data to encrypt using the Consumer/Producer model.";
	Crypter::RSA rsa(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	auto encrypted_consumer = rsa.Encrypt(consumer);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = rsa.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	auto decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty());
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
// =========================================================================
// Hybrid (Envelope) tests
// =========================================================================
int TestRSAEncryptDecryptHybrid(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecryptHybrid";
	const std::string message = "This is a hybrid envelope test message for RSA.";
	Crypter::RSA rsa(kp);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Hybrid
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	ASSERT_FALSE(fn_name, encrypted_data.Empty());
	FIFO decrypted_data;
	auto decrypt_result = rsa.Decrypt(
		std::span<const std::byte>(encrypted_data.Data().data(), encrypted_data.Data().size()),
		decrypted_data
	);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());
	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}
int TestRSAEncryptDecryptHybridStreaming(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecryptHybridStreaming";
	const std::string input_data = "This is some data to encrypt using Hybrid envelope with Consumer/Producer model (RSA).";
	Crypter::RSA rsa(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	auto encrypted_consumer = rsa.Encrypt(consumer, Crypter::Asymmetric::Strategy::Hybrid);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = rsa.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	auto decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty());
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestRSAHybridVsNativeDifferentOutput(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAHybridVsNativeDifferentOutput";
	const std::string message = "Same message for both modes";
	Crypter::RSA rsa(kp);
	FIFO native_encrypted;
	auto native_ok = rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		native_encrypted,
		Crypter::Asymmetric::Strategy::Native
	);
	ASSERT_TRUE(fn_name, native_ok);
	FIFO hybrid_encrypted;
	auto hybrid_ok = rsa.Encrypt(
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
int TestRSAEncryptDecryptNativeExplicit(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecryptNativeExplicit";
	const std::string message = "Explicit Native strategy round-trip for RSA.";
	Crypter::RSA rsa(kp);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Native
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	ASSERT_FALSE(fn_name, encrypted_data.Empty());
	FIFO decrypted_data;
	auto decrypt_result = rsa.Decrypt(
		std::span<const std::byte>(encrypted_data.Data().data(), encrypted_data.Data().size()),
		decrypted_data
	);
	ASSERT_TRUE(fn_name, decrypt_result);
	std::string decrypted_message = StormByte::String::FromByteVector(decrypted_data.Data());
	ASSERT_EQUAL(fn_name, decrypted_message, message);
	RETURN_TEST(fn_name, 0);
}
int TestRSAEncryptDecryptNativeExplicitStreaming(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAEncryptDecryptNativeExplicitStreaming";
	const std::string input_data = "Native explicit streaming with auto-detect decrypt (RSA).";
	Crypter::RSA rsa(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	StormByte::Buffer::Consumer consumer(producer.Consumer());
	auto encrypted_consumer = rsa.Encrypt(consumer, Crypter::Asymmetric::Strategy::Native);
	ASSERT_TRUE(fn_name, encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = rsa.Decrypt(encrypted_consumer);
	ASSERT_TRUE(fn_name, decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	auto decrypted_data = ReadAllFromConsumer(decrypted_consumer);
	ASSERT_FALSE(fn_name, decrypted_data.Empty());
	std::string decrypt_result = DeserializeString(decrypted_data);
	ASSERT_EQUAL(fn_name, input_data, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
// =========================================================================
// Corruption / mismatch edge cases for auto-detect
// =========================================================================
int TestRSACorruptedHybridEnvelopeFails(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSACorruptedHybridEnvelopeFails";
	const std::string message = "Hybrid envelope that will be corrupted.";
	Crypter::RSA rsa(kp);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Hybrid
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	auto corrupted = StormByte::String::FromByteVector(encrypted_data.Data());
	ASSERT_FALSE(fn_name, corrupted.empty());
	if (corrupted.size() > 8) {
		corrupted[0] = static_cast<char>(~corrupted[0]);
		corrupted[corrupted.size() / 3] = static_cast<char>(corrupted[corrupted.size() / 3] ^ 0x5A);
		corrupted[corrupted.size() - 1] = static_cast<char>(~corrupted[corrupted.size() - 1]);
	} else {
		corrupted[0] = static_cast<char>(~corrupted[0]);
	}
	FIFO decrypted_data;
	auto decrypt_result = rsa.Decrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted.data()), corrupted.size()),
		decrypted_data
	);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestRSACorruptedNativeFailsAutoDetect(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSACorruptedNativeFailsAutoDetect";
	const std::string message = "Native ciphertext that will be corrupted.";
	Crypter::RSA rsa(kp);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(
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
	auto decrypt_result = rsa.Decrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted.data()), corrupted.size()),
		decrypted_data
	);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int TestRSAHybridDecryptWithMismatchedKey(KeyPair::Generic::PointerType kp) {
	const std::string fn_name = "TestRSAHybridDecryptWithMismatchedKey";
	const std::string message = "Hybrid ciphertext, wrong private key.";
	Crypter::RSA rsa(kp);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(fn_name, kp2);
	Crypter::RSA rsa2(kp2);
	FIFO encrypted_data;
	auto encrypt_result = rsa.Encrypt(
		std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()),
		encrypted_data,
		Crypter::Asymmetric::Strategy::Hybrid
	);
	ASSERT_TRUE(fn_name, encrypt_result);
	FIFO decrypted_data;
	auto decrypt_result = rsa2.Decrypt(
		std::span<const std::byte>(encrypted_data.Data().data(), encrypted_data.Data().size()),
		decrypted_data
	);
	ASSERT_FALSE(fn_name, decrypt_result);
	RETURN_TEST(fn_name, 0);
}
int main() {
	int result = 0;
	const int key_strength = 2048;
	auto kp_asym_result = KeyPair::RSA::Generate(key_strength);
	if (!kp_asym_result) {
		std::cerr << "Failed to generate RSA asymmetric keypair" << std::endl;
		return 1;
	}
	auto kp_asym = kp_asym_result;
	result += TestRSAEncryptDecrypt(kp_asym);
	result += TestRSADecryptionWithCorruptedData(kp_asym);
	result += TestRSADecryptWithMismatchedKey(kp_asym);
	result += TestRSAWithCorruptedKeys(kp_asym);
	result += TestRSAEncryptionProducesDifferentContent(kp_asym);
	result += TestRSAEncryptDecryptUsingConsumerProducer(kp_asym);
	result += TestRSAEncryptDecryptHybrid(kp_asym);
	result += TestRSAEncryptDecryptHybridStreaming(kp_asym);
	result += TestRSAHybridVsNativeDifferentOutput(kp_asym);
	result += TestRSAEncryptDecryptNativeExplicit(kp_asym);
	result += TestRSAEncryptDecryptNativeExplicitStreaming(kp_asym);
	result += TestRSACorruptedHybridEnvelopeFails(kp_asym);
	result += TestRSACorruptedNativeFailsAutoDetect(kp_asym);
	result += TestRSAHybridDecryptWithMismatchedKey(kp_asym);
	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}
