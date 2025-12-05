#include <StormByte/crypto/implementation/encryption/chacha20.hxx>

#include <algorithm>
#include <chacha.h>
#include <cryptlib.h>
#include <hex.h>
#include <filters.h>
#include <format>
#include <osrng.h>
#include <secblock.h>
#include <thread>
#include <pwdbased.h>
#include <span>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	ExpectedCryptoBuffer EncryptHelper(std::span<const std::byte> dataSpan, const std::string& password) noexcept {
		try {
			// ChaCha20 requires a 256-bit (32-byte) key and a 96-bit (12-byte) IV/nonce
			CryptoPP::SecByteBlock salt(16);
			CryptoPP::SecByteBlock iv(12); // ChaCha20 uses 96-bit nonce
			CryptoPP::AutoSeededRandomPool rng;
			rng.GenerateBlock(salt, salt.size());
			rng.GenerateBlock(iv, iv.size());

			// Derive 256-bit key from password
			CryptoPP::SecByteBlock key(32);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
							password.size(), salt, salt.size(), 10000);

			std::vector<uint8_t> encryptedData;
			CryptoPP::ChaCha::Encryption encryption(key, key.size(), iv);
			CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes(), true,
									new CryptoPP::StreamTransformationFilter(encryption,
																			new CryptoPP::VectorSink(encryptedData),
																			CryptoPP::StreamTransformationFilter::NO_PADDING));

			// Prepend salt and IV to encrypted data
			encryptedData.insert(encryptedData.begin(), salt.begin(), salt.end());
			encryptedData.insert(encryptedData.begin() + salt.size(), iv.begin(), iv.end());

			std::vector<std::byte> convertedData(encryptedData.size());
			std::transform(encryptedData.begin(), encryptedData.end(), convertedData.begin(),
						[](uint8_t byte) { return static_cast<std::byte>(byte); });

			StormByte::Buffer::FIFO buffer;
			(void)buffer.Write(convertedData);
			return buffer;
		} catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}

	ExpectedCryptoBuffer DecryptHelper(std::span<const std::byte> encryptedSpan, const std::string& password) noexcept {
		try {
			const size_t saltSize = 16;
			const size_t ivSize = 12; // ChaCha20 nonce size

			if (encryptedSpan.size_bytes() < saltSize + ivSize) {
				return StormByte::Unexpected<StormByte::Crypto::Exception>("Encrypted data too short to contain salt and IV");
			}

			CryptoPP::SecByteBlock salt(saltSize), iv(ivSize);
			std::memcpy(salt.data(), encryptedSpan.data(), saltSize);
			std::memcpy(iv.data(), encryptedSpan.data() + saltSize, ivSize);

			encryptedSpan = encryptedSpan.subspan(saltSize + ivSize);

			// Derive 256-bit key from password
			CryptoPP::SecByteBlock key(32);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
							password.size(), salt, salt.size(), 10000);

			std::vector<uint8_t> decryptedData;
			CryptoPP::ChaCha::Decryption decryption(key, key.size(), iv);
			CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes(), true,
									new CryptoPP::StreamTransformationFilter(decryption,
																			new CryptoPP::VectorSink(decryptedData),
																			CryptoPP::StreamTransformationFilter::NO_PADDING));

			std::vector<std::byte> convertedData(decryptedData.size());
			std::transform(decryptedData.begin(), decryptedData.end(), convertedData.begin(),
				[](uint8_t byte) { return static_cast<std::byte>(byte); });

			StormByte::Buffer::FIFO buffer;
			(void)buffer.Write(convertedData);
			return buffer;
		} catch (const std::exception& e) {
			return StormByte::Unexpected<StormByte::Crypto::Exception>(e.what());
		}
	}
}

// Encrypt Function Overloads
ExpectedCryptoBuffer ChaCha20::Encrypt(const std::string& input, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return EncryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer ChaCha20::Encrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return EncryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer ChaCha20::Encrypt(Buffer::Consumer consumer, const std::string& password) noexcept {
	StormByte::Buffer::Producer producer;

	// Generate and write header synchronously before starting async processing
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::SecByteBlock salt(16);
	CryptoPP::SecByteBlock iv(12); // ChaCha20 nonce
	rng.GenerateBlock(salt, salt.size());
	rng.GenerateBlock(iv, iv.size());

	CryptoPP::SecByteBlock key(32);
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
	pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
					password.size(), salt, salt.size(), 10000);

	// Write salt and IV to output
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
			CryptoPP::ChaCha::Encryption encryption(key, key.size(), iv);
			std::vector<uint8_t> encryptedChunk;

			// Batch writes to reduce internal reallocations
			std::vector<std::byte> batchBuffer;
			batchBuffer.reserve(chunkSize * 2);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				// Use Span for zero-copy read
				auto spanResult = consumer.Extract(bytesToRead);
				if (!spanResult.has_value()) {
					producer.Close();
					return;
				}

				const auto& inputSpan = spanResult.value();
				encryptedChunk.clear();

				CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(inputSpan.data()), inputSpan.size(), true,
										new CryptoPP::StreamTransformationFilter(encryption,
																		new CryptoPP::VectorSink(encryptedChunk),
																		CryptoPP::StreamTransformationFilter::NO_PADDING));

				// Accumulate into batch buffer
				for (size_t i = 0; i < encryptedChunk.size(); ++i) {
					batchBuffer.push_back(static_cast<std::byte>(encryptedChunk[i]));
				}

				// Write in larger batches
				if (batchBuffer.size() >= chunkSize) {
					(void)producer.Write(std::move(batchBuffer));
					batchBuffer.clear();
					batchBuffer.reserve(chunkSize * 2);
					// Clean consumed data periodically
					consumer.Clean();
				}
			}
			// Write any remaining data
			if (!batchBuffer.empty()) {
				(void)producer.Write(std::move(batchBuffer));
			}
			producer.Close();
		} catch (...) {
			producer.Close();
		}
	}).detach();

	return producer.Consumer();
}

// Decrypt Function Overloads
ExpectedCryptoBuffer ChaCha20::Decrypt(const std::string& input, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer ChaCha20::Decrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return DecryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer ChaCha20::Decrypt(Buffer::Consumer consumer, const std::string& password) noexcept {
	StormByte::Buffer::Producer producer;

	std::thread([consumer, producer, password]() mutable {
		try {
			constexpr size_t chunkSize = 4096;
			CryptoPP::SecByteBlock salt(16);
			CryptoPP::SecByteBlock iv(12); // ChaCha20 nonce

			// Read salt
			while (consumer.AvailableBytes() < salt.size()) {
				if (!consumer.IsWritable() && consumer.AvailableBytes() < salt.size()) {
					producer.Close();
					return;
				}
				std::this_thread::yield();
			}
			auto saltSpan = consumer.Extract(salt.size());
			if (!saltSpan.has_value()) {
				producer.Close();
				return;
			}
			std::copy_n(reinterpret_cast<const uint8_t*>(saltSpan.value().data()), salt.size(), salt.data());

			// Read IV
			while (consumer.AvailableBytes() < iv.size()) {
				if (!consumer.IsWritable() && consumer.AvailableBytes() < iv.size()) {
					producer.Close();
					return;
				}
				std::this_thread::yield();
			}
			auto ivSpan = consumer.Extract(iv.size());
			if (!ivSpan.has_value()) {
				producer.Close();
				return;
			}
			std::copy_n(reinterpret_cast<const uint8_t*>(ivSpan.value().data()), iv.size(), iv.data());

			// Derive key
			CryptoPP::SecByteBlock key(32);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
							password.size(), salt, salt.size(), 10000);

			CryptoPP::ChaCha::Decryption decryption(key, key.size(), iv);
			std::vector<uint8_t> decryptedChunk;

			// Batch writes to reduce internal reallocations
			std::vector<std::byte> batchBuffer;
			batchBuffer.reserve(chunkSize * 2);

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				// Use Span for zero-copy read
				auto spanResult = consumer.Extract(bytesToRead);
				if (!spanResult.has_value()) {
					producer.Close();
					return;
				}

				const auto& encryptedSpan = spanResult.value();
				decryptedChunk.clear();

				CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size(), true,
										new CryptoPP::StreamTransformationFilter(decryption,
																		new CryptoPP::VectorSink(decryptedChunk),
																		CryptoPP::StreamTransformationFilter::NO_PADDING));

				// Accumulate into batch buffer
				for (size_t i = 0; i < decryptedChunk.size(); ++i) {
					batchBuffer.push_back(static_cast<std::byte>(decryptedChunk[i]));
				}

				// Write in larger batches
				if (batchBuffer.size() >= chunkSize) {
					(void)producer.Write(std::move(batchBuffer));
					batchBuffer.clear();
					batchBuffer.reserve(chunkSize * 2);
					// Clean consumed data periodically
					consumer.Clean();
				}
			}
			// Write any remaining data
			if (!batchBuffer.empty()) {
				(void)producer.Write(std::move(batchBuffer));
			}
			producer.Close();
		} catch (...) {
			producer.Close();
		}
	}).detach();

	return producer.Consumer();
}

// RandomPassword Function
ExpectedCryptoString ChaCha20::RandomPassword(const size_t& passwordSize) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::SecByteBlock password(passwordSize);
		rng.GenerateBlock(password, passwordSize);

		std::string passwordString;
		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(passwordString));
		encoder.Put(password.data(), password.size());
		encoder.MessageEnd();

		return passwordString;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("Failed to generate random password: {}", e.what());
	}
}
