#include <StormByte/crypto/implementation/encryption/camellia.hxx>

#include <algorithm>
#include <camellia.h>
#include <cryptlib.h>
#include <hex.h>
#include <modes.h>
#include <filters.h>
#include <format>
#include <osrng.h>
#include <secblock.h>
#include <thread>
#include <pwdbased.h>
#include <iomanip>
#include <span>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	ExpectedCryptoBuffer EncryptHelper(std::span<const std::byte> dataSpan, const std::string& password) noexcept {
		try {
			CryptoPP::SecByteBlock salt(16);
			CryptoPP::SecByteBlock iv(CryptoPP::Camellia::BLOCKSIZE);
			CryptoPP::AutoSeededRandomPool rng;
			rng.GenerateBlock(salt, salt.size());
			rng.GenerateBlock(iv, iv.size());

			CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
							password.size(), salt, salt.size(), 10000);

			std::vector<uint8_t> encryptedData;
			CryptoPP::CBC_Mode<CryptoPP::Camellia>::Encryption encryption(key, key.size(), iv);
			CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes(), true,
									new CryptoPP::StreamTransformationFilter(encryption,
																			new CryptoPP::VectorSink(encryptedData)));

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
			const size_t ivSize = CryptoPP::Camellia::BLOCKSIZE;

			if (encryptedSpan.size_bytes() < saltSize + ivSize) {
				return StormByte::Unexpected<StormByte::Crypto::Exception>("Encrypted data too short to contain salt and IV");
			}

			CryptoPP::SecByteBlock salt(saltSize), iv(ivSize);
			std::memcpy(salt.data(), encryptedSpan.data(), saltSize);
			std::memcpy(iv.data(), encryptedSpan.data() + saltSize, ivSize);

			encryptedSpan = encryptedSpan.subspan(saltSize + ivSize);

			CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
							password.size(), salt, salt.size(), 10000);

			std::vector<uint8_t> decryptedData;
			CryptoPP::CBC_Mode<CryptoPP::Camellia>::Decryption decryption(key, key.size(), iv);
			CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes(), true,
									new CryptoPP::StreamTransformationFilter(decryption,
																			new CryptoPP::VectorSink(decryptedData)));

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
ExpectedCryptoBuffer Camellia::Encrypt(const std::string& input, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return EncryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer Camellia::Encrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return EncryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer Camellia::Encrypt(Buffer::Consumer consumer, const std::string& password) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	// Generate and write header synchronously before starting async processing
	// This prevents race condition where consumer is used before header exists
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::SecByteBlock salt(16);
	CryptoPP::SecByteBlock iv(CryptoPP::Camellia::BLOCKSIZE);
	rng.GenerateBlock(salt, salt.size());
	rng.GenerateBlock(iv, iv.size());

	CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
	pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
					password.size(), salt, salt.size(), 10000);

	// Write salt and IV to output in a single batch
	std::vector<std::byte> headerBytes;
	headerBytes.reserve(salt.size() + iv.size());
	for (size_t i = 0; i < salt.size(); ++i) {
		headerBytes.push_back(static_cast<std::byte>(salt[i]));
	}
	for (size_t i = 0; i < iv.size(); ++i) {
		headerBytes.push_back(static_cast<std::byte>(iv[i]));
	}
	(void)producer->Write(std::move(headerBytes));

	// Now start async encryption with the derived key and IV
	std::thread([consumer, producer, key = std::move(key), iv = std::move(iv)]() mutable {
		try {
			(void)consumer.AvailableBytes();
			constexpr size_t chunkSize = 4096;
			CryptoPP::CBC_Mode<CryptoPP::Camellia>::Encryption encryption(key, key.size(), iv);
			std::vector<uint8_t> encryptedChunk;

			while (!consumer.EoF()) {
				(void)consumer.AvailableBytes();
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				// Use Read() to obtain an owned copy to avoid span lifetime races across threads
				auto readResult = consumer.Extract(bytesToRead);
				if (!readResult.has_value()) {
					producer->Close();
					return;
				}

				const auto& inputVec = readResult.value();
				encryptedChunk.clear();

				CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(inputVec.data()), inputVec.size(), true,
										new CryptoPP::StreamTransformationFilter(encryption,
																		new CryptoPP::VectorSink(encryptedChunk)));

				std::vector<std::byte> byteData;
				byteData.reserve(encryptedChunk.size());
				for (size_t i = 0; i < encryptedChunk.size(); ++i) {
					byteData.push_back(static_cast<std::byte>(encryptedChunk[i]));
				}
				(void)producer->Write(byteData);
			}
			producer->Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer->Close();
		}
	}).detach();

	return producer->Consumer();
}

// Decrypt Function Overloads
ExpectedCryptoBuffer Camellia::Decrypt(const std::string& input, const std::string& password) noexcept {
	std::span<const std::byte> dataSpan(reinterpret_cast<const std::byte*>(input.data()), input.size());
	return DecryptHelper(dataSpan, password);
}

ExpectedCryptoBuffer Camellia::Decrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept {
	auto data = const_cast<StormByte::Buffer::FIFO&>(input).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<StormByte::Crypto::Exception>("Failed to extract data from input buffer");
	}
	std::span<const std::byte> dataSpan(data.value().data(), data.value().size());
	return DecryptHelper(dataSpan, password);
}

StormByte::Buffer::Consumer Camellia::Decrypt(Buffer::Consumer consumer, const std::string& password) noexcept {
	SharedProducerBuffer producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, password]() mutable {
		try {
			(void)consumer.AvailableBytes();
			constexpr size_t chunkSize = 4096;
			CryptoPP::SecByteBlock salt(16);
			CryptoPP::SecByteBlock iv(CryptoPP::Camellia::BLOCKSIZE);

			// Block until salt is available. Use Read() to obtain an owned buffer
			// so the memory won't be freed while we copy it out.
			auto saltRead = consumer.Extract(salt.size());
			if (!saltRead.has_value()) {
				producer->Close();
				return;
			}
			const auto& saltVec = saltRead.value();
			std::copy_n(reinterpret_cast<const uint8_t*>(saltVec.data()), salt.size(), salt.data());

			// Block until IV is available and copy into local SecByteBlock.
			auto ivRead = consumer.Extract(iv.size());
			if (!ivRead.has_value()) {
				producer->Close();
				return;
			}
			const auto& ivVec = ivRead.value();
			std::copy_n(reinterpret_cast<const uint8_t*>(ivVec.data()), iv.size(), iv.data());

			CryptoPP::SecByteBlock key(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
			pbkdf2.DeriveKey(key, key.size(), 0, reinterpret_cast<const uint8_t*>(password.data()),
							password.size(), salt, salt.size(), 10000);

			CryptoPP::CBC_Mode<CryptoPP::Camellia>::Decryption decryption(key, key.size(), iv);
			std::vector<uint8_t> decryptedChunk;

			while (!consumer.EoF()) {
				(void)consumer.AvailableBytes();
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				// Use Read() to obtain an owned copy to avoid span lifetime races across threads
				auto readResult = consumer.Extract(bytesToRead);
				if (!readResult.has_value()) {
					producer->Close();
					return;
				}

				const auto& encryptedVec = readResult.value();
				decryptedChunk.clear();

				CryptoPP::StringSource ss(reinterpret_cast<const uint8_t*>(encryptedVec.data()), encryptedVec.size(), true,
										new CryptoPP::StreamTransformationFilter(decryption,
																		new CryptoPP::VectorSink(decryptedChunk)));

				std::vector<std::byte> byteData;
				byteData.reserve(decryptedChunk.size());
				for (size_t i = 0; i < decryptedChunk.size(); ++i) {
					byteData.push_back(static_cast<std::byte>(decryptedChunk[i]));
				}
				(void)producer->Write(byteData);
			}
			producer->Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer->Close();
		}
	}).detach();

	return producer->Consumer();
}

// RandomPassword Function
ExpectedCryptoString Camellia::RandomPassword(const size_t& passwordSize) noexcept {
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
