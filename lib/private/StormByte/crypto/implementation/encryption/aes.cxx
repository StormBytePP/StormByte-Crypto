#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/implementation/encryption/aes.hxx>

#include <algorithm>
#include <aes.h>
#include <cryptlib.h>
#include <hex.h>
#include <modes.h>
#include <filters.h>
#include <format>
#include <secblock.h>
#include <thread>
#include <pwdbased.h>
#include <iomanip>
#include <span>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	ExpectedCryptoBuffer EncryptHelper(std::span<const std::byte> dataSpan, const std::string& password) noexcept {
		try {
			CryptoPP::SecByteBlock salt(16);
			CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

			CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key,
				key.size(),
				0,
				reinterpret_cast<const uint8_t*>(password.data()),
				password.size(),
				salt,
				salt.size(),
				10000
			);

			std::vector<uint8_t> encryptedData;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(key, key.size(), iv);
			CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(dataSpan.data()),
				dataSpan.size_bytes(),
				true,
				new CryptoPP::StreamTransformationFilter(
					encryption,
					new CryptoPP::VectorSink(encryptedData)
				)
			);

			encryptedData.insert(encryptedData.begin(), salt.begin(), salt.end());
			encryptedData.insert(encryptedData.begin() + salt.size(), iv.begin(), iv.end());

			FIFO buffer;
			(void)buffer.Write(std::move(encryptedData));
			return buffer;
		} catch (const std::exception& e) {
			return Unexpected(CrypterException(e.what()));
		}
	}

	ExpectedCryptoBuffer DecryptHelper(std::span<const std::byte> encryptedSpan, const std::string& password) noexcept {
		try {
			const size_t saltSize = 16;
			const size_t ivSize = CryptoPP::AES::BLOCKSIZE;

			if (encryptedSpan.size_bytes() < saltSize + ivSize) {
				return Unexpected(CrypterException("Encrypted data too short to contain salt and IV"));
			}

			CryptoPP::SecByteBlock salt(saltSize), iv(ivSize);
			std::memcpy(salt.data(), encryptedSpan.data(), saltSize);
			std::memcpy(iv.data(), encryptedSpan.data() + saltSize, ivSize);

			encryptedSpan = encryptedSpan.subspan(saltSize + ivSize);

			CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(
				key,
				key.size(),
				0,
				reinterpret_cast<const uint8_t*>(password.data()),
				password.size(),
				salt,
				salt.size(),
				10000
			);

			std::vector<uint8_t> decryptedData;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, key.size(), iv);
			CryptoPP::StringSource ss(
				reinterpret_cast<const uint8_t*>(encryptedSpan.data()),
				encryptedSpan.size_bytes(),
				true,
				new CryptoPP::StreamTransformationFilter(
					decryption,
					new CryptoPP::VectorSink(decryptedData)
				)
			);

		FIFO buffer;
		(void)buffer.Write(std::move(decryptedData));
		return buffer;
	} catch (const std::exception& e) {
		return Unexpected(StormByte::Crypto::Exception(e.what()));
		}
	}
}

// Encrypt Function Overloads
ExpectedCryptoBuffer AES::Encrypt(const std::string& input, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return EncryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer AES::Encrypt(const FIFO& input, const std::string& password) noexcept {
	DataType data;
	auto read_ok = input.Read(data);
	if (!read_ok.has_value()) {
		return Unexpected(StormByte::Crypto::Exception("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return EncryptHelper(dataSpan, password);
}

Consumer AES::Encrypt(Consumer consumer, const std::string& password) noexcept {
	Producer producer;

	// Generate and write header synchronously before starting async processing
	// This prevents race condition where consumer is used before header exists
	CryptoPP::SecByteBlock salt(16);
	CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
	RNG().GenerateBlock(salt, salt.size());
	RNG().GenerateBlock(iv, iv.size());

	CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
	pbkdf2.DeriveKey(
		key,
		key.size(),
		0,
		reinterpret_cast<const uint8_t*>(password.data()),
		password.size(),
		salt,
		salt.size(),
		10000
	);

	// Write salt and IV to output in a single batch
	std::vector<std::byte> headerBytes;
	headerBytes.reserve(salt.size() + iv.size());
	for (size_t i = 0; i < salt.size(); ++i) {
		headerBytes.push_back(static_cast<std::byte>(salt[i]));
	}
	for (size_t i = 0; i < iv.size(); ++i) {
		headerBytes.push_back(static_cast<std::byte>(iv[i]));
	}
	(void)producer.Write(std::move(headerBytes));

	// Now start async encryption with the derived key and IV
	std::thread([consumer, producer, key = std::move(key), iv = std::move(iv)]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(key, key.size(), iv);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				std::vector<uint8_t> encryptedChunk;
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto readResult = consumer.Extract(bytesToRead, data);
				if (!readResult.has_value()) {
					producer.SetError();
					return;
				}

				CryptoPP::StringSource ss(
					reinterpret_cast<const uint8_t*>(data.data()),
					data.size(),
					true,
					new CryptoPP::StreamTransformationFilter(
						encryption,
						new CryptoPP::VectorSink(encryptedChunk)
					)
				);

				(void)producer.Write(std::move(encryptedChunk));
			}
			producer.Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

// Decrypt Function Overloads
ExpectedCryptoBuffer AES::Decrypt(const std::string& input, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer AES::Decrypt(const FIFO& input, const std::string& password) noexcept {
	DataType data;
	auto read_ok = input.Read(data);
	if (!read_ok.has_value()) {
		return StormByte::Unexpected(CrypterException("Failed to extract data from input buffer"));
	}
	std::span<const std::byte> dataSpan(data.data(), data.size());
	return DecryptHelper(dataSpan, password);
}

Consumer AES::Decrypt(Consumer consumer, const std::string& password) noexcept {
	Producer producer;

	std::thread([consumer, producer, password]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			CryptoPP::SecByteBlock salt(16);
			CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

			// Block until salt is available. Use Read() to obtain an owned buffer
			// so the memory won't be freed while we copy it out.
			DataType saltData;
			auto saltRead = consumer.Extract(salt.size(), saltData);
			if (!saltRead.has_value()) {
				producer.SetError();
				return;
			}

			std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()), salt.size(), salt.data());

			// Block until IV is available and copy into local SecByteBlock.
			DataType ivData;
			auto ivRead = consumer.Extract(iv.size(), ivData);
			if (!ivRead.has_value()) {
				producer.SetError();
				return;
			}
			std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()), iv.size(), iv.data());

			CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(
				key,
				key.size(),
				0,
				reinterpret_cast<const uint8_t*>(password.data()),
				password.size(),
				salt,
				salt.size(),
				10000
			);

			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, key.size(), iv);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				std::vector<uint8_t> decryptedChunk;
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto readResult = consumer.Extract(bytesToRead, data);
				if (!readResult.has_value()) {
					producer.SetError();
					return;
				}

				CryptoPP::StringSource ss(
					reinterpret_cast<const uint8_t*>(data.data()),
					data.size(),
					true,
					new CryptoPP::StreamTransformationFilter(
						decryption,
						new CryptoPP::VectorSink(decryptedChunk)
					)
				);

				(void)producer.Write(std::move(decryptedChunk));
			}
			producer.Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

// RandomPassword Function
ExpectedCryptoString AES::RandomPassword(const size_t& passwordSize) noexcept {
	try {
		CryptoPP::SecByteBlock password(passwordSize);
		RNG().GenerateBlock(password, passwordSize);

		std::string passwordString;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(passwordString));
		encoder.Put(password.data(), password.size());
		encoder.MessageEnd();

		return passwordString;
	} catch (const std::exception& e) {
		return Unexpected(CrypterException("Failed to generate random password: {}", e.what()));
	}
}