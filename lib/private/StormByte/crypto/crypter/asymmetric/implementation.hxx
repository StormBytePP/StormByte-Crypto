#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>

#include <thread>
#include <span>
#include <secblock.h>
#include <gcm.h>
#include <aes.h>
#include <integer.h>
#include <memory>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

namespace StormByte::Crypto::Crypter {

	// =========================================================================
	// Native Asymmetric Encrypt
	// =========================================================================

	template<typename CryptorT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptAsymmetric(std::span<const std::byte> dataSpan, KeyPair::Generic::PointerType keypair, WriteOnly& output) noexcept {
		if (!keypair) return false;
		try {
			auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(keypair->PublicKey());
			if (!keyRes) return false;
			PublicKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3)) return false;

			CryptorT pkEncryptor(key);
			DataType encryptedData;
			CryptoPP::PK_EncryptorFilter pkf(RNG(), pkEncryptor, new CryptoPP::StringSinkTemplate<DataType>(encryptedData));
			pkf.Put(reinterpret_cast<const CryptoPP::byte*>(dataSpan.data()), dataSpan.size_bytes());
			pkf.MessageEnd();
			return output.Write(std::move(encryptedData));
		} catch (...) {
			return false;
		}
	}

	template<typename CryptorT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptAsymmetric(Consumer consumer, const KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		Producer producer;

		if (!keypair) {
			producer.SetError();
			return producer.Consumer();
		}

		std::thread([consumer, producer, keypair, mode]() mutable {
			try {
				if (!keypair) { producer.SetError(); return; }
				auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(keypair->PublicKey());
				if (!keyRes) { producer.SetError(); return; }
				PublicKeyT key = std::move(*keyRes);
				if (!key.Validate(RNG(), 3)) { producer.SetError(); return; }

				constexpr size_t chunkSize = 4096;
				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) { std::this_thread::yield(); continue; }

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool readResult;
					if (mode == ReadMode::Copy) readResult = consumer.Read(bytesToRead, data);
					else readResult = consumer.Extract(bytesToRead, data);
					if (!readResult) { producer.SetError(); return; }

					CryptorT pkEncryptor(key);
					DataType encryptedChunk;
					CryptoPP::PK_EncryptorFilter pkf(RNG(), pkEncryptor, new CryptoPP::StringSinkTemplate<DataType>(encryptedChunk));
					pkf.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
					pkf.MessageEnd();

					if (!producer.Write(std::move(encryptedChunk))) { producer.SetError(); return; }
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}
		}).detach();

		return producer.Consumer();
	}

	// =========================================================================
	// Hybrid Envelope Encrypt
	// =========================================================================

	template<typename EncryptorT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool EncryptAsymmetricBlockEnvelope(
		std::span<const std::byte> dataSpan,
		KeyPair::Generic::PointerType keypair,
		WriteOnly& output) noexcept
	{
		CryptoPP::SecByteBlock symKey;
		CryptoPP::SecByteBlock iv;
		try {
			if (!keypair) return false;

			auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(keypair->PublicKey());
			if (!keyRes) return false;
			PublicKeyT pubKey = std::move(*keyRes);
			if (!pubKey.Validate(RNG(), 3)) return false;

			constexpr size_t symKeyLen = 32;
			constexpr size_t ivLen = 12;
			symKey.CleanNew(symKeyLen);
			iv.CleanNew(ivLen);
			RNG().GenerateBlock(symKey, symKey.size());
			RNG().GenerateBlock(iv, iv.size());

			CryptoPP::GCM<CryptoPP::AES>::Encryption aead;
			aead.SetKeyWithIV(symKey, symKey.size(), iv, ivLen);

			DataType ciphertext;
			CryptoPP::AuthenticatedEncryptionFilter ef(
				aead,
				new CryptoPP::StringSinkTemplate<DataType>(ciphertext)
			);
			ef.Put(reinterpret_cast<const CryptoPP::byte*>(dataSpan.data()), dataSpan.size_bytes());
			ef.MessageEnd();

			EncryptorT pkEncryptor(pubKey);
			DataType esk;
			CryptoPP::PK_EncryptorFilter pkf(
				RNG(),
				pkEncryptor,
				new CryptoPP::StringSinkTemplate<DataType>(esk)
			);
			pkf.Put(symKey.data(), symKey.size());
			pkf.MessageEnd();

			Helpers::SecureWipe(symKey);

			uint32_t eskLen = static_cast<uint32_t>(esk.size());
			DataType finalData;
			finalData.reserve(4 + esk.size() + ivLen + ciphertext.size());

			finalData.push_back(static_cast<std::byte>((eskLen >> 24) & 0xFF));
			finalData.push_back(static_cast<std::byte>((eskLen >> 16) & 0xFF));
			finalData.push_back(static_cast<std::byte>((eskLen >> 8) & 0xFF));
			finalData.push_back(static_cast<std::byte>(eskLen & 0xFF));

			finalData.insert(finalData.end(), esk.begin(), esk.end());
			Helpers::SecureWipe(esk);

			for (size_t i = 0; i < ivLen; ++i)
				finalData.push_back(static_cast<std::byte>(iv[i]));
			finalData.insert(finalData.end(), ciphertext.begin(), ciphertext.end());

			Helpers::SecureWipe(iv);

			return output.Write(std::move(finalData));
		}
		catch (...) {
			Helpers::SecureWipe(symKey);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename EncryptorT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer EncryptAsymmetricBlockEnvelope(
		Consumer consumer,
		KeyPair::Generic::PointerType keypair,
		ReadMode mode) noexcept
	{
		Producer producer;

		if (!keypair) {
			producer.SetError();
			return producer.Consumer();
		}

		CryptoPP::SecByteBlock symKey;
		CryptoPP::SecByteBlock iv;
		try {
			auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(keypair->PublicKey());
			if (!keyRes) {
				producer.SetError();
				return producer.Consumer();
			}
			PublicKeyT pubKey = std::move(*keyRes);
			if (!pubKey.Validate(RNG(), 3)) {
				producer.SetError();
				return producer.Consumer();
			}

			constexpr size_t symKeyLen = 32;
			constexpr size_t ivLen = 12;
			symKey.CleanNew(symKeyLen);
			iv.CleanNew(ivLen);
			RNG().GenerateBlock(symKey, symKey.size());
			RNG().GenerateBlock(iv, iv.size());

			EncryptorT pkEncryptor(pubKey);
			DataType esk;
			CryptoPP::PK_EncryptorFilter pkf(
				RNG(),
				pkEncryptor,
				new CryptoPP::StringSinkTemplate<DataType>(esk)
			);
			pkf.Put(symKey.data(), symKey.size());
			pkf.MessageEnd();

			uint32_t eskLen = static_cast<uint32_t>(esk.size());
			DataType header;
			header.reserve(4 + esk.size() + ivLen);
			header.push_back(static_cast<std::byte>((eskLen >> 24) & 0xFF));
			header.push_back(static_cast<std::byte>((eskLen >> 16) & 0xFF));
			header.push_back(static_cast<std::byte>((eskLen >> 8) & 0xFF));
			header.push_back(static_cast<std::byte>(eskLen & 0xFF));
			header.insert(header.end(), esk.begin(), esk.end());
			Helpers::SecureWipe(esk);
			for (size_t i = 0; i < ivLen; ++i)
				header.push_back(static_cast<std::byte>(iv[i]));

			if (!producer.Write(std::move(header))) {
				Helpers::SecureWipe(symKey);
				Helpers::SecureWipe(iv);
				producer.SetError();
				return producer.Consumer();
			}

			std::thread([consumer, producer, symKey = std::move(symKey), iv = std::move(iv), mode]() mutable {
				try {
					CryptoPP::GCM<CryptoPP::AES>::Encryption aead;
					aead.SetKeyWithIV(symKey, symKey.size(), iv, iv.size());

					DataType encryptedChunk;
					CryptoPP::AuthenticatedEncryptionFilter ef(
						aead,
						new CryptoPP::StringSinkTemplate<DataType>(encryptedChunk)
					);

					constexpr size_t chunkSize = 4096;
					while (!consumer.EoF()) {
						size_t availableBytes = consumer.AvailableBytes();
						if (availableBytes == 0) {
							std::this_thread::yield();
							continue;
						}

						size_t bytesToRead = std::min(availableBytes, chunkSize);
						DataType data;
						bool readResult = (mode == ReadMode::Copy)
							? consumer.Read(bytesToRead, data)
							: consumer.Extract(bytesToRead, data);

						if (!readResult) {
							producer.SetError();
							Helpers::SecureWipe(symKey);
							Helpers::SecureWipe(iv);
							return;
						}

						ef.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());

						if (!encryptedChunk.empty()) {
							if (!producer.Write(std::move(encryptedChunk))) {
								producer.SetError();
								Helpers::SecureWipe(symKey);
								Helpers::SecureWipe(iv);
								return;
							}
							encryptedChunk.clear();
						}
					}

					ef.MessageEnd();
					if (!encryptedChunk.empty()) {
						if (!producer.Write(std::move(encryptedChunk))) {
							producer.SetError();
							Helpers::SecureWipe(symKey);
							Helpers::SecureWipe(iv);
							return;
						}
					}
					producer.Close();
				}
				catch (...) {
					producer.SetError();
				}

				Helpers::SecureWipe(symKey);
				Helpers::SecureWipe(iv);
			}).detach();

			return producer.Consumer();
		}
		catch (...) {
			Helpers::SecureWipe(symKey);
			Helpers::SecureWipe(iv);
			producer.SetError();
			return producer.Consumer();
		}
	}

	// =========================================================================
	// Native Asymmetric Decrypt
	// =========================================================================

	template<typename DecryptorT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptAsymmetric(std::span<const std::byte> encryptedSpan, KeyPair::Generic::PointerType keypair, WriteOnly& output) noexcept {
		if (!keypair || !keypair->HasPrivateKey()) return false;
		try {
			auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(*keypair->PrivateKey());
			if (!keyRes) return false;
			PrivateKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3)) return false;

			DecryptorT pkDecryptor(key);
			DataType decryptedData;
			CryptoPP::PK_DecryptorFilter pkdf(RNG(), pkDecryptor, new CryptoPP::StringSinkTemplate<DataType>(decryptedData));
			pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(encryptedSpan.data()), encryptedSpan.size_bytes());
			pkdf.MessageEnd();

			return output.Write(std::move(decryptedData));
		} catch (...) {
			return false;
		}
	}

	template<typename DecryptorT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptAsymmetric(Consumer consumer, KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		Producer producer;
		if (!keypair || !keypair->HasPrivateKey()) {
			producer.SetError();
			return producer.Consumer();
		}

		Password privKey = *keypair->PrivateKey();

		std::thread([consumer, producer, privKey = std::move(privKey), mode]() mutable {
			try {
				auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
				if (!keyRes) { producer.SetError(); return; }
				PrivateKeyT key = std::move(*keyRes);
				if (!key.Validate(RNG(), 3)) { producer.SetError(); return; }

				constexpr size_t chunkSize = 4096;
				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) { std::this_thread::yield(); continue; }

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool read_result;
					if (mode == ReadMode::Copy) read_result = consumer.Read(bytesToRead, data);
					else read_result = consumer.Extract(bytesToRead, data);
					if (!read_result) { producer.SetError(); return; }

					DecryptorT pkDecryptor(key);
					DataType decryptedChunk;
					CryptoPP::PK_DecryptorFilter pkdf(RNG(), pkDecryptor, new CryptoPP::StringSinkTemplate<DataType>(decryptedChunk));
					pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
					pkdf.MessageEnd();

					if (!producer.Write(std::move(decryptedChunk))) { producer.SetError(); return; }
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}
		}).detach();

		return producer.Consumer();
	}

	// =========================================================================
	// Hybrid Envelope Decrypt
	// =========================================================================

	template<typename DecryptorT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptAsymmetricBlockEnvelope(std::span<const std::byte> encryptedSpan, KeyPair::Generic::PointerType keypair, WriteOnly& output) noexcept {
		CryptoPP::SecByteBlock iv;
		CryptoPP::SecByteBlock symKey;
		if (!keypair || !keypair->HasPrivateKey()) return false;

		try {
			if (encryptedSpan.size_bytes() < 4)
				return false;

			uint32_t esk_len = (static_cast<uint32_t>(std::to_integer<unsigned char>(encryptedSpan[0])) << 24) |
							(static_cast<uint32_t>(std::to_integer<unsigned char>(encryptedSpan[1])) << 16) |
							(static_cast<uint32_t>(std::to_integer<unsigned char>(encryptedSpan[2])) << 8)  |
							(static_cast<uint32_t>(std::to_integer<unsigned char>(encryptedSpan[3])));

			size_t pos = 4;
			if (encryptedSpan.size_bytes() < pos + esk_len + 12)
				return false;

			DataType eskData(esk_len);
			std::memcpy(eskData.data(), encryptedSpan.data() + pos, esk_len);
			pos += esk_len;

			constexpr size_t ivLen = 12;
			iv.CleanNew(ivLen);
			std::memcpy(iv.data(), encryptedSpan.data() + pos, ivLen);
			pos += ivLen;

			auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(*keypair->PrivateKey());
			if (!keyRes) {
				Helpers::SecureWipe(eskData);
				Helpers::SecureWipe(iv);
				return false;
			}
			PrivateKeyT priv = std::move(*keyRes);
			if (!priv.Validate(RNG(), 3)) {
				Helpers::SecureWipe(eskData);
				Helpers::SecureWipe(iv);
				return false;
			}

			DecryptorT pkDecryptor(priv);
			DataType symKeyData;
			{
				CryptoPP::PK_DecryptorFilter pkdf(RNG(), pkDecryptor, new CryptoPP::StringSinkTemplate<DataType>(symKeyData));
				pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(eskData.data()), eskData.size());
				pkdf.MessageEnd();
			}
			Helpers::SecureWipe(eskData);

			if (symKeyData.empty()) {
				Helpers::SecureWipe(iv);
				return false;
			}
			symKey.Assign(reinterpret_cast<const CryptoPP::byte*>(symKeyData.data()), symKeyData.size());
			Helpers::SecureWipe(symKeyData);

			size_t payloadLen = encryptedSpan.size_bytes() - pos;
			const CryptoPP::byte* payloadPtr = reinterpret_cast<const CryptoPP::byte*>(encryptedSpan.data() + pos);

			CryptoPP::GCM<CryptoPP::AES>::Decryption aead;
			aead.SetKeyWithIV(symKey, symKey.size(), iv, ivLen);

			DataType out;
			CryptoPP::AuthenticatedDecryptionFilter df(
				aead,
				new CryptoPP::StringSinkTemplate<DataType>(out),
				CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
			);
			if (payloadLen > 0) df.Put(payloadPtr, payloadLen);
			df.MessageEnd();

			Helpers::SecureWipe(symKey);
			Helpers::SecureWipe(iv);

			return output.Write(std::move(out));
		} catch (...) {
			Helpers::SecureWipe(symKey);
			Helpers::SecureWipe(iv);
			return false;
		}
	}

	template<typename DecryptorT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptAsymmetricBlockEnvelope(
		Consumer consumer,
		KeyPair::Generic::PointerType keypair,
		ReadMode mode) noexcept
	{
		Producer producer;

		if (!keypair || !keypair->HasPrivateKey()) {
			producer.SetError();
			return producer.Consumer();
		}

		Password privKey = *keypair->PrivateKey();

		std::thread([consumer, producer, privKey = std::move(privKey), mode]() mutable {
			CryptoPP::SecByteBlock iv;
			CryptoPP::SecByteBlock symKey;
			try {
				constexpr size_t ivLen = 12;

				while (consumer.AvailableBytes() < 4 && !consumer.EoF())
					std::this_thread::yield();
				if (consumer.AvailableBytes() < 4) {
					producer.SetError();
					return;
				}

				DataType lenBytes;
				bool ok = (mode == ReadMode::Copy)
					? consumer.Read(4, lenBytes)
					: consumer.Extract(4, lenBytes);
				if (!ok || lenBytes.size() != 4) {
					producer.SetError();
					return;
				}

				uint32_t esk_len = (static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[0])) << 24) |
								(static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[1])) << 16) |
								(static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[2])) << 8)  |
								(static_cast<uint32_t>(std::to_integer<unsigned char>(lenBytes[3])));

				const size_t headerRest = esk_len + ivLen;
				while (consumer.AvailableBytes() < headerRest && !consumer.EoF())
					std::this_thread::yield();
				if (consumer.AvailableBytes() < headerRest) {
					producer.SetError();
					return;
				}

				DataType eskData;
				ok = (mode == ReadMode::Copy)
					? consumer.Read(esk_len, eskData)
					: consumer.Extract(esk_len, eskData);
				if (!ok || eskData.size() != esk_len) {
					producer.SetError();
					return;
				}

				DataType ivData;
				ok = (mode == ReadMode::Copy)
					? consumer.Read(ivLen, ivData)
					: consumer.Extract(ivLen, ivData);
				if (!ok || ivData.size() != ivLen) {
					Helpers::SecureWipe(eskData);
					producer.SetError();
					return;
				}

				iv.CleanNew(ivLen);
				std::memcpy(iv.data(), ivData.data(), ivLen);
				Helpers::SecureWipe(ivData);

				auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
				if (!keyRes) {
					Helpers::SecureWipe(eskData);
					Helpers::SecureWipe(iv);
					producer.SetError();
					return;
				}
				PrivateKeyT priv = std::move(*keyRes);
				if (!priv.Validate(RNG(), 3)) {
					Helpers::SecureWipe(eskData);
					Helpers::SecureWipe(iv);
					producer.SetError();
					return;
				}

				DecryptorT pkDecryptor(priv);
				DataType symKeyData;
				{
					CryptoPP::PK_DecryptorFilter pkdf(
						RNG(),
						pkDecryptor,
						new CryptoPP::StringSinkTemplate<DataType>(symKeyData)
					);
					pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(eskData.data()), eskData.size());
					pkdf.MessageEnd();
				}
				Helpers::SecureWipe(eskData);

				if (symKeyData.empty()) {
					Helpers::SecureWipe(iv);
					producer.SetError();
					return;
				}

				symKey.Assign(reinterpret_cast<const CryptoPP::byte*>(symKeyData.data()), symKeyData.size());
				Helpers::SecureWipe(symKeyData);

				CryptoPP::GCM<CryptoPP::AES>::Decryption aead;
				aead.SetKeyWithIV(symKey, symKey.size(), iv, ivLen);

				DataType decryptedChunk;
				CryptoPP::AuthenticatedDecryptionFilter df(
					aead,
					new CryptoPP::StringSinkTemplate<DataType>(decryptedChunk),
					CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS
				);

				constexpr size_t chunkSize = 4096;
				while (!consumer.EoF()) {
					size_t available = consumer.AvailableBytes();
					if (available == 0) {
						std::this_thread::yield();
						continue;
					}

					size_t toRead = std::min(available, chunkSize);
					DataType data;
					bool readOk = (mode == ReadMode::Copy)
						? consumer.Read(toRead, data)
						: consumer.Extract(toRead, data);

					if (!readOk) {
						producer.SetError();
						Helpers::SecureWipe(symKey);
						Helpers::SecureWipe(iv);
						return;
					}

					df.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());

					if (!decryptedChunk.empty()) {
						if (!producer.Write(std::move(decryptedChunk))) {
							producer.SetError();
							Helpers::SecureWipe(symKey);
							Helpers::SecureWipe(iv);
							return;
						}
						decryptedChunk.clear();
					}
				}

				try {
					df.MessageEnd();
				} catch (...) {
					producer.SetError();
					Helpers::SecureWipe(symKey);
					Helpers::SecureWipe(iv);
					return;
				}

				if (!decryptedChunk.empty()) {
					if (!producer.Write(std::move(decryptedChunk))) {
						producer.SetError();
						Helpers::SecureWipe(symKey);
						Helpers::SecureWipe(iv);
						return;
					}
				}

				producer.Close();
				Helpers::SecureWipe(symKey);
				Helpers::SecureWipe(iv);
			}
			catch (...) {
				Helpers::SecureWipe(symKey);
				Helpers::SecureWipe(iv);
				producer.SetError();
			}
		}).detach();

		return producer.Consumer();
	}
}
