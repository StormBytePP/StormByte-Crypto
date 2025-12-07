#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>

#include <gcm.h>
#include <pwdbased.h>
#include <secblock.h>
#include <span>
#include <thread>
#include <cstring>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

namespace StormByte::Crypto::Crypter {
	template<typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE size_t DeriveKey(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, const std::string& password) noexcept {
		CryptoPP::PKCS5_PBKDF2_HMAC<CryptoHMAC> pbkdf2;
		return pbkdf2.DeriveKey(
			key,
			key.size(),
			0,
			reinterpret_cast<const uint8_t*>(password.data()),
			password.size(),
			salt,
			salt.size(),
			10000
		);
	}

	// Portable SetKey+IV helper: prefer SetKeyWithIV when available, otherwise
	// fall back to SetKeyWithoutResync + Resync (used by ChaCha20Poly1305)
	template<typename CryptorT>
	auto SetKeyIVImpl(CryptorT& c, const CryptoPP::SecByteBlock& key, size_t keylen, const CryptoPP::SecByteBlock& iv, size_t ivlen, int) -> decltype(c.SetKeyWithIV(key, keylen, iv, ivlen), void()) {
		c.SetKeyWithIV(key, keylen, iv, ivlen);
	}

	template<typename CryptorT>
	void SetKeyIVImpl(CryptorT& c, const CryptoPP::SecByteBlock& key, size_t keylen, const CryptoPP::SecByteBlock& iv, size_t ivlen, long) {
		// Many AuthenticatedSymmetricCipher implementations expose SetKeyWithoutResync/Resync
		c.SetKeyWithoutResync(key.data(), keylen, CryptoPP::g_nullNameValuePairs);
		c.Resync(iv.data(), static_cast<int>(ivlen));
	}

	template<typename CryptorT>
	void SetKeyIV(CryptorT& c, const CryptoPP::SecByteBlock& key, size_t keylen, const CryptoPP::SecByteBlock& iv, size_t ivlen) {
		SetKeyIVImpl(c, key, keylen, iv, ivlen, 0);
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptCBC(std::span<const std::byte> dataSpan, const std::string& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		try {
			CryptoPP::SecByteBlock salt(salt_size);
			CryptoPP::SecByteBlock iv(iv_size);
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

			CryptoPP::SecByteBlock key(key_size);
			DeriveKey<CryptoHMAC>(key, salt, password);

			DataType encryptedData;
			CryptorT encryption(key, key.size(), iv);
			CryptoPP::StringSource ss(
				reinterpret_cast<const uint8_t*>(dataSpan.data()),
				dataSpan.size_bytes(),
				true,
				new CryptoPP::StreamTransformationFilter(
					encryption,
					new CryptoPP::StringSinkTemplate<DataType>(encryptedData)
				)
			);

			// Prepend salt and IV (header) before the ciphertext so that
			// Decrypt functions can read header first.
			DataType finalData;
			finalData.reserve(salt.size() + iv.size() + encryptedData.size());
			for (size_t i = 0; i < salt.size(); ++i) finalData.push_back(static_cast<std::byte>(salt[i]));
			for (size_t i = 0; i < iv.size(); ++i) finalData.push_back(static_cast<std::byte>(iv[i]));
			finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

			return output.Write(std::move(finalData));
		} catch (...) {
			return false;
		}
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptCBC(Consumer consumer, const std::string& password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		Producer producer;

		// Generate and write header synchronously before starting async processing
		// This prevents race condition where consumer is used before header exists
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		RNG().GenerateBlock(salt, salt.size());
		RNG().GenerateBlock(iv, iv.size());

		CryptoPP::SecByteBlock key(key_size);
		DeriveKey<CryptoHMAC>(key, salt, password);

		// Write salt and IV to output in a single batch
		std::vector<std::byte> headerBytes;
		headerBytes.reserve(salt.size() + iv.size());
		for (size_t i = 0; i < salt.size(); ++i) {
			headerBytes.push_back(static_cast<std::byte>(salt[i]));
		}
		for (size_t i = 0; i < iv.size(); ++i) {
			headerBytes.push_back(static_cast<std::byte>(iv[i]));
		}
		if (!producer.Write(std::move(headerBytes))) {
			producer.SetError();
			return producer.Consumer();
		}

		// Now start async encryption with the derived key and IV
		std::thread([consumer, producer, key = std::move(key), mode, iv = std::move(iv)]() mutable {
			try {
				constexpr size_t chunkSize = 4096;
				CryptorT encryption(key, key.size(), iv);

				// Reuse a single StreamTransformationFilter across chunks to avoid
				// per-chunk allocations. The filter writes into encryptedChunk which
				// we will move into the producer and then clear.
				DataType encryptedChunk;
				CryptoPP::StreamTransformationFilter filter(
					encryption,
					new CryptoPP::StringSinkTemplate<DataType>(encryptedChunk)
				);

				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) {
						std::this_thread::yield();
						continue;
					}

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool readResult;
					if (mode == ReadMode::Copy)
						readResult = consumer.Read(bytesToRead, data);
					else
						readResult = consumer.Extract(bytesToRead, data);

					if (!readResult) {
						producer.SetError();
						return;
					}

					// Feed data into the filter; the produced bytes are appended to encryptedChunk
					filter.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!encryptedChunk.empty()) {
						if (!producer.Write(std::move(encryptedChunk))) {
							producer.SetError();
							return;
						}
						encryptedChunk.clear();
					}
				}

				// Finalize filter and flush any remaining output
				filter.MessageEnd();
				if (!encryptedChunk.empty()) {
					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						return;
					}
				}
				producer.Close(); // Mark processing complete // Update status (EOF or Error)
			} catch (...) {
				producer.SetError();
			}
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT,typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptGCM(std::span<const std::byte> dataSpan, const std::string& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		try {
			CryptoPP::SecByteBlock salt(salt_size);
			CryptoPP::SecByteBlock iv(iv_size);
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

			// Derive key from password
			CryptoPP::SecByteBlock key(key_size);
			DeriveKey<CryptoHMAC>(key, salt, password);

			// Encrypt using GCM mode
			DataType encryptedData;
			CryptorT encryption;
			SetKeyIV(encryption, key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedEncryptionFilter ef(encryption,
				new CryptoPP::StringSinkTemplate<DataType>(encryptedData)
			);

			if (!aad.empty()) {
				ef.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
			}

			ef.Put(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes());
			ef.MessageEnd();

			// Prepend salt and IV (header) before the ciphertext so that
			// Decrypt functions can read header first.
			DataType finalData;
			finalData.reserve(salt.size() + iv.size() + encryptedData.size());
			for (size_t i = 0; i < salt.size(); ++i) finalData.push_back(static_cast<std::byte>(salt[i]));
			for (size_t i = 0; i < iv.size(); ++i) finalData.push_back(static_cast<std::byte>(iv[i]));
			finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

			return output.Write(std::move(finalData));
		} catch (...) {
			return false;
		}
	}

	template<typename AlgoT,typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptGCM(Consumer consumer, const std::string& password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		// Generate and write header synchronously before starting async processing
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		RNG().GenerateBlock(salt, salt.size());
		RNG().GenerateBlock(iv, iv.size());

		CryptoPP::SecByteBlock key(key_size);
		DeriveKey<CryptoHMAC>(key, salt, password);

		// Write salt and IV to output in a single batch
		std::vector<std::byte> headerBytes;
		headerBytes.reserve(salt.size() + iv.size());
		for (size_t i = 0; i < salt.size(); ++i) headerBytes.push_back(static_cast<std::byte>(salt[i]));
		for (size_t i = 0; i < iv.size(); ++i) headerBytes.push_back(static_cast<std::byte>(iv[i]));
		if (!producer.Write(std::move(headerBytes))) {
			producer.SetError();
			return producer.Consumer();
		}

		std::thread([consumer, producer, key = std::move(key), mode,iv = std::move(iv), aad]() mutable {
			try {
				constexpr size_t chunkSize = 4096;

				CryptorT encryption;
				SetKeyIV(encryption, key, key.size(), iv, iv.size());

					DataType encryptedChunk;
				CryptoPP::AuthenticatedEncryptionFilter ef(
					encryption,
					new CryptoPP::StringSinkTemplate<DataType>(encryptedChunk)
				);

				if (!aad.empty()) {
					ef.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
				}

				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) { std::this_thread::yield(); continue; }

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool readResult;
					if (mode == ReadMode::Copy)
						readResult = consumer.Read(bytesToRead, data);
					else
						readResult = consumer.Extract(bytesToRead, data);
					if (!readResult) { producer.SetError(); return; }

					ef.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						return;
					}
					encryptedChunk.clear();
				}

				ef.MessageEnd();
				if (!encryptedChunk.empty())
					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						return;
					}
				producer.Close();
			} catch (...) { producer.SetError(); }
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptAEAD(std::span<const std::byte> dataSpan, const std::string& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		try {
			CryptoPP::SecByteBlock salt(salt_size);
			CryptoPP::SecByteBlock iv(iv_size);
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

			CryptoPP::SecByteBlock key(key_size);
			DeriveKey<CryptoHMAC>(key, salt, password);

			DataType encryptedData;
			CryptorT encryption;
			SetKeyIV(encryption, key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedEncryptionFilter ef(
				encryption,
				new CryptoPP::StringSinkTemplate<DataType>(encryptedData)
			);

			// Feed optional AAD (Additional Authenticated Data) into the filter on channel "AAD"
			if (!aad.empty()) {
				ef.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
			}

			ef.Put(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes());
			ef.MessageEnd();

			// Prepend salt and IV (header) before the ciphertext so that
			// Decrypt functions can read header first.
			DataType finalData;
			finalData.reserve(salt.size() + iv.size() + encryptedData.size());
			for (size_t i = 0; i < salt.size(); ++i) finalData.push_back(static_cast<std::byte>(salt[i]));
			for (size_t i = 0; i < iv.size(); ++i) finalData.push_back(static_cast<std::byte>(iv[i]));
			finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

			return output.Write(std::move(finalData));
		} catch (...) {
			return false;
		}
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptAEAD(Consumer consumer, const std::string& password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		// Generate and write header synchronously before starting async processing
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		RNG().GenerateBlock(salt, salt.size());
		RNG().GenerateBlock(iv, iv.size());

		CryptoPP::SecByteBlock key(key_size);
		DeriveKey<CryptoHMAC>(key, salt, password);

		// Write salt and IV to output in a single batch
		std::vector<std::byte> headerBytes;
		headerBytes.reserve(salt.size() + iv.size());
		for (size_t i = 0; i < salt.size(); ++i) headerBytes.push_back(static_cast<std::byte>(salt[i]));
		for (size_t i = 0; i < iv.size(); ++i) headerBytes.push_back(static_cast<std::byte>(iv[i]));
		if (!producer.Write(std::move(headerBytes))) {
			producer.SetError();
			return producer.Consumer();
		}

		std::thread([consumer, producer, key = std::move(key), mode, iv = std::move(iv), aad]() mutable {
			try {
				constexpr size_t chunkSize = 4096;

				CryptorT encryption;
				SetKeyIV(encryption, key, key.size(), iv, iv.size());

				DataType encryptedChunk;
				CryptoPP::AuthenticatedEncryptionFilter ef(
					encryption,
					new CryptoPP::StringSinkTemplate<DataType>(encryptedChunk)
				);

				if (!aad.empty()) {
					ef.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
				}

				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) { std::this_thread::yield(); continue; }

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool read_result;
					if (mode == ReadMode::Copy)
						read_result = consumer.Read(bytesToRead, data);
					else
						read_result = consumer.Extract(bytesToRead, data);
					if (!read_result) {
						producer.SetError();
						return;
					}

					ef.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						return;
					}
					encryptedChunk.clear();
				}

				ef.MessageEnd();
				if (!encryptedChunk.empty()) {
					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						return;
					}
				}
				producer.Close();
			} catch (...) { producer.SetError(); }
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptCBC(std::span<const std::byte> dataSpan, const std::string& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		try {
			if (dataSpan.size_bytes() < salt_size + iv_size) {
				return false;
			}

			CryptoPP::SecByteBlock salt(salt_size), iv(iv_size);
			std::memcpy(salt.data(), dataSpan.data(), salt_size);
			std::memcpy(iv.data(), dataSpan.data() + salt_size, iv_size);

			auto payload = dataSpan.subspan(salt_size + iv_size);

			CryptoPP::SecByteBlock key(key_size);
			DeriveKey<CryptoHMAC>(key, salt, password);

			DataType decryptedData;
			DecryptorT decryption(key, key.size(), iv);
			CryptoPP::StringSource ss(
				reinterpret_cast<const uint8_t*>(payload.data()),
				payload.size_bytes(),
				true,
					new CryptoPP::StreamTransformationFilter(
					decryption,
					new CryptoPP::StringSinkTemplate<DataType>(decryptedData)
				)
			);

			return output.Write(std::move(decryptedData));
		} catch (...) {
			return false;
		}
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptCBC(Consumer consumer, const std::string& password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		Producer producer;

		std::thread([consumer, producer, password, mode, salt_size, iv_size, key_size]() mutable {
			try {
				constexpr size_t chunkSize = 4096;
				CryptoPP::SecByteBlock salt(salt_size);
				CryptoPP::SecByteBlock iv(iv_size);

				// Block until salt is available. Use Extract to obtain an owned buffer
				// so the memory won't be freed while we copy it out.
				DataType saltData;
				auto saltRead = consumer.Extract(salt.size(), saltData);
				if (!saltRead) {
					producer.SetError();
					return;
				}

				std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()), salt.size(), salt.data());

				// Block until IV is available and copy into local SecByteBlock.
				DataType ivData;
				auto ivRead = consumer.Extract(iv.size(), ivData);
				if (!ivRead) {
					producer.SetError();
					return;
				}
				std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()), iv.size(), iv.data());

				CryptoPP::SecByteBlock key(key_size);
				DeriveKey<CryptoHMAC>(key, salt, password);

				DecryptorT decryption(key, key.size(), iv);

				// Reuse a single StreamTransformationFilter for decryption across chunks
				DataType decryptedChunk;
				CryptoPP::StreamTransformationFilter filter(
					decryption,
					new CryptoPP::StringSinkTemplate<DataType>(decryptedChunk)
				);

				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) {
						std::this_thread::yield();
						continue;
					}

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool readResult;
					if (mode == ReadMode::Copy)
						readResult = consumer.Read(bytesToRead, data);
					else
						readResult = consumer.Extract(bytesToRead, data);
					if (!readResult) {
						producer.SetError();
						return;
					}

					filter.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!decryptedChunk.empty()) {
						if (!producer.Write(std::move(decryptedChunk))) {
							producer.SetError();
							return;
						}
						decryptedChunk.clear();
					}
				}

				filter.MessageEnd();
				if (!decryptedChunk.empty()) {
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						return;
					}
				}
				producer.Close(); // Mark processing complete // Update status (EOF or Error)
			} catch (...) {
				producer.SetError();
			}
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptGCM(std::span<const std::byte> encryptedSpan, const std::string& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		try {
			if (encryptedSpan.size_bytes() < salt_size + iv_size) {
				return false;
			}

			CryptoPP::SecByteBlock salt(salt_size), iv(iv_size);
			std::memcpy(salt.data(), encryptedSpan.data(), salt_size);
			std::memcpy(iv.data(), encryptedSpan.data() + salt_size, iv_size);

			encryptedSpan = encryptedSpan.subspan(salt_size + iv_size);

			// Derive key from password
			CryptoPP::SecByteBlock key(key_size);
			DeriveKey<CryptoHMAC>(key, salt, password);

			// Decrypt using GCM mode
			DataType decryptedData;
			DecryptorT decryption;
			SetKeyIV(decryption, key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedDecryptionFilter df(
				decryption,
				new CryptoPP::StringSinkTemplate<DataType>(decryptedData),
				CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
			);

			df.Put(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes());
			df.MessageEnd();

			return output.Write(std::move(decryptedData));
		} catch (...) {
			return false;
		}
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptGCM(Consumer consumer, const std::string& password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		std::thread([consumer, producer, password, mode, salt_size, iv_size, key_size, aad]() mutable {
			try {
				constexpr size_t chunkSize = 4096;
				CryptoPP::SecByteBlock salt(salt_size);
				CryptoPP::SecByteBlock iv(iv_size);

				// Block until salt is available. Use Extract to obtain owned buffer
				DataType saltData;
				auto saltRead = consumer.Extract(salt.size(), saltData);
				if (!saltRead) { producer.SetError(); return; }
				std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()), salt.size(), salt.data());

				// Block until IV is available and copy into local SecByteBlock.
				DataType ivData;
				auto ivRead = consumer.Extract(iv.size(), ivData);
				if (!ivRead) { producer.SetError(); return; }
				std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()), iv.size(), iv.data());

				CryptoPP::SecByteBlock key(key_size);
				DeriveKey<CryptoHMAC>(key, salt, password);

				DecryptorT decryption;
				SetKeyIV(decryption, key, key.size(), iv, iv.size());

				DataType decryptedChunk;
				CryptoPP::AuthenticatedDecryptionFilter df(
					decryption,
					new CryptoPP::StringSinkTemplate<DataType>(decryptedChunk),
					CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
				);

				if (!aad.empty()) {
					df.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
				}

				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) { std::this_thread::yield(); continue; }

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool readResult;
					if (mode == ReadMode::Copy)
						readResult = consumer.Read(bytesToRead, data);
					else
						readResult = consumer.Extract(bytesToRead, data);
					if (!readResult) { producer.SetError(); return; }

					df.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						return;
					}
					decryptedChunk.clear();
				}

				try { df.MessageEnd(); } catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed&) { producer.SetError(); return; }

				if (!decryptedChunk.empty()) {
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						return;
					}
				}
				producer.Close();
			} catch (...) { producer.SetError(); }
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptAEAD(std::span<const std::byte> encryptedSpan, const std::string& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		try {
			if (encryptedSpan.size_bytes() < salt_size + iv_size) {
				return false;
			}

			CryptoPP::SecByteBlock salt(salt_size), iv(iv_size);
			std::memcpy(salt.data(), encryptedSpan.data(), salt_size);
			std::memcpy(iv.data(), encryptedSpan.data() + salt_size, iv_size);

			encryptedSpan = encryptedSpan.subspan(salt_size + iv_size);

			CryptoPP::SecByteBlock key(key_size);
			DeriveKey<CryptoHMAC>(key, salt, password);

			DataType decryptedData;
			DecryptorT decryption;
			SetKeyIV(decryption, key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedDecryptionFilter df(
				decryption,
				new CryptoPP::StringSinkTemplate<DataType>(decryptedData),
				CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
			);

			// Provide AAD on the "AAD" channel when present
			if (!aad.empty()) {
				df.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
			}

			df.Put(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes());
			df.MessageEnd();

			return output.Write(std::move(decryptedData));
		} catch (...) {
			return false;
		}
	}	

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptAEAD(Consumer consumer, const std::string& password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		std::thread([consumer, producer, password, mode, salt_size, iv_size, key_size, aad]() mutable {
			try {
				constexpr size_t chunkSize = 4096;
				CryptoPP::SecByteBlock salt(salt_size);
				CryptoPP::SecByteBlock iv(iv_size);

				DataType saltData;
				auto saltRead = consumer.Extract(salt.size(), saltData);
				if (!saltRead) { producer.SetError(); return; }
				std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()), salt.size(), salt.data());

				DataType ivData;
				auto ivRead = consumer.Extract(iv.size(), ivData);
				if (!ivRead) { producer.SetError(); return; }
				std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()), iv.size(), iv.data());

				CryptoPP::SecByteBlock key(key_size);
				DeriveKey<CryptoHMAC>(key, salt, password);

				DecryptorT decryption;
				SetKeyIV(decryption, key, key.size(), iv, iv.size());

				DataType decryptedChunk;
				CryptoPP::AuthenticatedDecryptionFilter df(
					decryption,
					new CryptoPP::StringSinkTemplate<DataType>(decryptedChunk),
					CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
				);

				if (!aad.empty()) {
					df.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
				}

				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) { std::this_thread::yield(); continue; }

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool readResult;
					if (mode == ReadMode::Copy)
						readResult = consumer.Read(bytesToRead, data);
					else
						readResult = consumer.Extract(bytesToRead, data);
					if (!readResult) { producer.SetError(); return; }

					df.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						return;
					}
					decryptedChunk.clear();
				}

				try { df.MessageEnd(); } catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed&) { producer.SetError(); return; }

				if (!decryptedChunk.empty()) {
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						return;
					}
				}
				producer.Close();
			} catch (...) { producer.SetError(); }
		}).detach();

		return producer.Consumer();
	}
}