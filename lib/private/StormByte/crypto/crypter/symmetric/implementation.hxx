#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/password.hxx>
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

	// OWASP Password Storage Cheat Sheet (2023): minimum 600_000 iterations for
	// PBKDF2-HMAC-SHA-256. Do not lower this without a documented security review;
	// fewer iterations weakens resistance to offline password cracking.
	constexpr unsigned int PBKDF2_ITERATIONS = 600000;

	template<typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE size_t DeriveKey(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, const Password& password) noexcept {
		CryptoPP::PKCS5_PBKDF2_HMAC<CryptoHMAC> pbkdf2;
		const unsigned char* pwdData = Helpers::PasswordAccess::Data(password);
		const std::size_t pwdSize = Helpers::PasswordAccess::Size(password);
		return pbkdf2.DeriveKey(
			key,
			key.size(),
			0,
			pwdData ? pwdData : reinterpret_cast<const uint8_t*>(""),
			pwdSize,
			salt,
			salt.size(),
			PBKDF2_ITERATIONS
		);
	}

	template<typename CryptorT>
	auto SetKeyIVImpl(CryptorT& c, const CryptoPP::SecByteBlock& key, size_t keylen, const CryptoPP::SecByteBlock& iv, size_t ivlen, int) -> decltype(c.SetKeyWithIV(key, keylen, iv, ivlen), void()) {
		c.SetKeyWithIV(key, keylen, iv, ivlen);
	}

	template<typename CryptorT>
	void SetKeyIVImpl(CryptorT& c, const CryptoPP::SecByteBlock& key, size_t keylen, const CryptoPP::SecByteBlock& iv, size_t ivlen, long) {
		c.SetKeyWithoutResync(key.data(), keylen, CryptoPP::g_nullNameValuePairs);
		c.Resync(iv.data(), static_cast<int>(ivlen));
	}

	template<typename CryptorT>
	void SetKeyIV(CryptorT& c, const CryptoPP::SecByteBlock& key, size_t keylen, const CryptoPP::SecByteBlock& iv, size_t ivlen) {
		SetKeyIVImpl(c, key, keylen, iv, ivlen, 0);
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptCBC(std::span<const std::byte> dataSpan, const Password& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		try {
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

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

			DataType finalData;
			finalData.reserve(salt.size() + iv.size() + encryptedData.size());
			for (size_t i = 0; i < salt.size(); ++i) finalData.push_back(static_cast<std::byte>(salt[i]));
			for (size_t i = 0; i < iv.size(); ++i) finalData.push_back(static_cast<std::byte>(iv[i]));
			finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);

			return output.Write(std::move(finalData));
		} catch (...) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptCBC(Consumer consumer, Password password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		Producer producer;

		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		RNG().GenerateBlock(salt, salt.size());
		RNG().GenerateBlock(iv, iv.size());

		DeriveKey<CryptoHMAC>(key, salt, password);

		std::vector<std::byte> headerBytes;
		headerBytes.reserve(salt.size() + iv.size());
		for (size_t i = 0; i < salt.size(); ++i)
			headerBytes.push_back(static_cast<std::byte>(salt[i]));
		for (size_t i = 0; i < iv.size(); ++i)
			headerBytes.push_back(static_cast<std::byte>(iv[i]));
		if (!producer.Write(std::move(headerBytes))) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			producer.SetError();
			return producer.Consumer();
		}

		Helpers::SecureWipe(salt);

		std::thread([consumer, producer, key = std::move(key), mode, iv = std::move(iv)]() mutable {
			try {
				constexpr size_t chunkSize = 4096;
				CryptorT encryption(key, key.size(), iv);

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
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}

					filter.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!encryptedChunk.empty()) {
						if (!producer.Write(std::move(encryptedChunk))) {
							producer.SetError();
							Helpers::SecureWipe(key);
							Helpers::SecureWipe(iv);
							return;
						}
						encryptedChunk.clear();
					}
				}

				filter.MessageEnd();
				if (!encryptedChunk.empty()) {
					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(iv);
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptGCM(std::span<const std::byte> dataSpan, const Password& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		try {
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

			DeriveKey<CryptoHMAC>(key, salt, password);

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

			DataType finalData;
			finalData.reserve(salt.size() + iv.size() + encryptedData.size());
			for (size_t i = 0; i < salt.size(); ++i) finalData.push_back(static_cast<std::byte>(salt[i]));
			for (size_t i = 0; i < iv.size(); ++i) finalData.push_back(static_cast<std::byte>(iv[i]));
			finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);

			return output.Write(std::move(finalData));
		} catch (...) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptGCM(Consumer consumer, Password password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		RNG().GenerateBlock(salt, salt.size());
		RNG().GenerateBlock(iv, iv.size());

		DeriveKey<CryptoHMAC>(key, salt, password);

		std::vector<std::byte> headerBytes;
		headerBytes.reserve(salt.size() + iv.size());
		for (size_t i = 0; i < salt.size(); ++i) headerBytes.push_back(static_cast<std::byte>(salt[i]));
		for (size_t i = 0; i < iv.size(); ++i) headerBytes.push_back(static_cast<std::byte>(iv[i]));
		if (!producer.Write(std::move(headerBytes))) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			producer.SetError();
			return producer.Consumer();
		}

		Helpers::SecureWipe(salt);

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
					bool readResult;
					if (mode == ReadMode::Copy)
						readResult = consumer.Read(bytesToRead, data);
					else
						readResult = consumer.Extract(bytesToRead, data);
					if (!readResult) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}

					ef.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}
					encryptedChunk.clear();
				}

				ef.MessageEnd();
				if (!encryptedChunk.empty()) {
					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(iv);
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptAEAD(std::span<const std::byte> dataSpan, const Password& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		try {
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());

			DeriveKey<CryptoHMAC>(key, salt, password);

			DataType encryptedData;
			CryptorT encryption;
			SetKeyIV(encryption, key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedEncryptionFilter ef(
				encryption,
				new CryptoPP::StringSinkTemplate<DataType>(encryptedData)
			);

			if (!aad.empty()) {
				ef.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
			}

			ef.Put(reinterpret_cast<const uint8_t*>(dataSpan.data()), dataSpan.size_bytes());
			ef.MessageEnd();

			DataType finalData;
			finalData.reserve(salt.size() + iv.size() + encryptedData.size());
			for (size_t i = 0; i < salt.size(); ++i) finalData.push_back(static_cast<std::byte>(salt[i]));
			for (size_t i = 0; i < iv.size(); ++i) finalData.push_back(static_cast<std::byte>(iv[i]));
			finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);

			return output.Write(std::move(finalData));
		} catch (...) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename AlgoT, typename CryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptAEAD(Consumer consumer, Password password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		RNG().GenerateBlock(salt, salt.size());
		RNG().GenerateBlock(iv, iv.size());

		DeriveKey<CryptoHMAC>(key, salt, password);

		std::vector<std::byte> headerBytes;
		headerBytes.reserve(salt.size() + iv.size());
		for (size_t i = 0; i < salt.size(); ++i) headerBytes.push_back(static_cast<std::byte>(salt[i]));
		for (size_t i = 0; i < iv.size(); ++i) headerBytes.push_back(static_cast<std::byte>(iv[i]));
		if (!producer.Write(std::move(headerBytes))) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			producer.SetError();
			return producer.Consumer();
		}

		Helpers::SecureWipe(salt);

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
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}

					ef.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}
					encryptedChunk.clear();
				}

				ef.MessageEnd();
				if (!encryptedChunk.empty()) {
					if (!producer.Write(std::move(encryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(iv);
						return;
					}
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(iv);
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptCBC(std::span<const std::byte> dataSpan, const Password& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		try {
			if (dataSpan.size_bytes() < salt_size + iv_size)
				return false;

			std::memcpy(salt.data(), dataSpan.data(), salt_size);
			std::memcpy(iv.data(), dataSpan.data() + salt_size, iv_size);

			auto payload = dataSpan.subspan(salt_size + iv_size);

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

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);

			return output.Write(std::move(decryptedData));
		} catch (...) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptCBC(Consumer consumer, Password password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		Producer producer;

		std::thread([consumer, producer, password = std::move(password), mode, salt_size, iv_size, key_size]() mutable {
			CryptoPP::SecByteBlock salt(salt_size);
			CryptoPP::SecByteBlock iv(iv_size);
			CryptoPP::SecByteBlock key(key_size);

			try {
				constexpr size_t chunkSize = 4096;

				DataType saltData;
				auto saltRead = consumer.Extract(salt.size(), saltData);
				if (!saltRead) {
					producer.SetError();
					return;
				}

				std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()), salt.size(), salt.data());

				DataType ivData;
				auto ivRead = consumer.Extract(iv.size(), ivData);
				if (!ivRead) {
					producer.SetError();
					Helpers::SecureWipe(salt);
					return;
				}
				std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()), iv.size(), iv.data());

				DeriveKey<CryptoHMAC>(key, salt, password);

				DecryptorT decryption(key, key.size(), iv);

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
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}

					filter.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());

					if (!decryptedChunk.empty()) {
						if (!producer.Write(std::move(decryptedChunk))) {
							producer.SetError();
							Helpers::SecureWipe(key);
							Helpers::SecureWipe(salt);
							Helpers::SecureWipe(iv);
							return;
						}
						decryptedChunk.clear();
					}
				}

				filter.MessageEnd();
				if (!decryptedChunk.empty()) {
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptGCM(std::span<const std::byte> encryptedSpan, const Password& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		try {
			if (encryptedSpan.size_bytes() < salt_size + iv_size)
				return false;

			std::memcpy(salt.data(), encryptedSpan.data(), salt_size);
			std::memcpy(iv.data(), encryptedSpan.data() + salt_size, iv_size);

			encryptedSpan = encryptedSpan.subspan(salt_size + iv_size);

			DeriveKey<CryptoHMAC>(key, salt, password);

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

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);

			return output.Write(std::move(decryptedData));
		} catch (...) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptGCM(Consumer consumer, Password password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		std::thread([consumer, producer, password = std::move(password), mode, salt_size, iv_size, key_size, aad]() mutable {
			CryptoPP::SecByteBlock salt(salt_size);
			CryptoPP::SecByteBlock iv(iv_size);
			CryptoPP::SecByteBlock key(key_size);

			try {
				constexpr size_t chunkSize = 4096;

				DataType saltData;
				auto saltRead = consumer.Extract(salt.size(), saltData);
				if (!saltRead) {
					producer.SetError();
					return;
				}
				std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()), salt.size(), salt.data());

				DataType ivData;
				auto ivRead = consumer.Extract(iv.size(), ivData);
				if (!ivRead) {
					producer.SetError();
					Helpers::SecureWipe(salt);
					return;
				}
				std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()), iv.size(), iv.data());

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
					if (!readResult) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}

					df.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}
					decryptedChunk.clear();
				}

				try {
					df.MessageEnd();
				} catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed&) {
					producer.SetError();
					Helpers::SecureWipe(key);
					Helpers::SecureWipe(salt);
					Helpers::SecureWipe(iv);
					return;
				}

				if (!decryptedChunk.empty()) {
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
		}).detach();

		return producer.Consumer();
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptAEAD(std::span<const std::byte> encryptedSpan, const Password& password, WriteOnly& output, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		CryptoPP::SecByteBlock salt(salt_size);
		CryptoPP::SecByteBlock iv(iv_size);
		CryptoPP::SecByteBlock key(key_size);

		try {
			if (encryptedSpan.size_bytes() < salt_size + iv_size)
				return false;

			std::memcpy(salt.data(), encryptedSpan.data(), salt_size);
			std::memcpy(iv.data(), encryptedSpan.data() + salt_size, iv_size);

			encryptedSpan = encryptedSpan.subspan(salt_size + iv_size);

			DeriveKey<CryptoHMAC>(key, salt, password);

			DataType decryptedData;
			DecryptorT decryption;
			SetKeyIV(decryption, key, key.size(), iv, iv.size());

			CryptoPP::AuthenticatedDecryptionFilter df(
				decryption,
				new CryptoPP::StringSinkTemplate<DataType>(decryptedData),
				CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
			);

			if (!aad.empty()) {
				df.ChannelPut2("AAD", reinterpret_cast<const CryptoPP::byte*>(aad.data()), aad.size_bytes(), 0, false);
			}

			df.Put(reinterpret_cast<const uint8_t*>(encryptedSpan.data()), encryptedSpan.size_bytes());
			df.MessageEnd();

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);

			return output.Write(std::move(decryptedData));
		} catch (...) {
			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename AlgoT, typename DecryptorT, typename CryptoHMAC>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptAEAD(Consumer consumer, Password password, ReadMode mode, const std::size_t& salt_size, const std::size_t& iv_size, const std::size_t& key_size = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		Producer producer;

		std::thread([consumer, producer, password = std::move(password), mode, salt_size, iv_size, key_size, aad]() mutable {
			CryptoPP::SecByteBlock salt(salt_size);
			CryptoPP::SecByteBlock iv(iv_size);
			CryptoPP::SecByteBlock key(key_size);

			try {
				constexpr size_t chunkSize = 4096;

				DataType saltData;
				auto saltRead = consumer.Extract(salt.size(), saltData);
				if (!saltRead) {
					producer.SetError();
					return;
				}
				std::copy_n(reinterpret_cast<const uint8_t*>(saltData.data()), salt.size(), salt.data());

				DataType ivData;
				auto ivRead = consumer.Extract(iv.size(), ivData);
				if (!ivRead) {
					producer.SetError();
					Helpers::SecureWipe(salt);
					return;
				}
				std::copy_n(reinterpret_cast<const uint8_t*>(ivData.data()), iv.size(), iv.data());

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
					if (!readResult) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}

					df.Put(reinterpret_cast<const uint8_t*>(data.data()), data.size());
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}
					decryptedChunk.clear();
				}

				try {
					df.MessageEnd();
				} catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed&) {
					producer.SetError();
					Helpers::SecureWipe(key);
					Helpers::SecureWipe(salt);
					Helpers::SecureWipe(iv);
					return;
				}

				if (!decryptedChunk.empty()) {
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(key);
						Helpers::SecureWipe(salt);
						Helpers::SecureWipe(iv);
						return;
					}
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}

			Helpers::SecureWipe(key);
			Helpers::SecureWipe(salt);
			Helpers::SecureWipe(iv);
		}).detach();

		return producer.Consumer();
	}
}
