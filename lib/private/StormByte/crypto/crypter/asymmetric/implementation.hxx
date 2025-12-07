#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>

#include <thread>
#include <span>
#include <iostream>
// For hybrid (envelope) mode
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
		template<typename CryptorT, typename PublicKeyT>
		STORMBYTE_CRYPTO_PRIVATE bool EncryptAsymmetric(std::span<const std::byte> dataSpan, KeyPair::Generic::PointerType keypair, WriteOnly& output) noexcept {
			if (!keypair) return false;
			try {
				// Deserialize and validate the public key
				auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(keypair->PublicKey());
				if (!keyRes) return false;
				PublicKeyT key = std::move(*keyRes);
				if (!key.Validate(RNG(), 3)) return false;

				// Perform pure asymmetric encryption of the provided span
				CryptorT pkEncryptor(key);
				DataType encryptedData;
				CryptoPP::PK_EncryptorFilter pkf(RNG(), pkEncryptor, new CryptoPP::StringSinkTemplate<DataType>(encryptedData));
				pkf.Put(reinterpret_cast<const CryptoPP::byte*>(dataSpan.data()), dataSpan.size_bytes());
				pkf.MessageEnd();
				return output.Write(std::move(encryptedData));
			} catch (...) { return false; }
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
				// Deserialize and validate the public key
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

					// Encrypt this chunk with PK
					CryptorT pkEncryptor(key);
					DataType encryptedChunk;
					CryptoPP::PK_EncryptorFilter pkf(RNG(), pkEncryptor, new CryptoPP::StringSinkTemplate<DataType>(encryptedChunk));
					pkf.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
					pkf.MessageEnd();

					if (!producer.Write(std::move(encryptedChunk))) { producer.SetError(); return; }
				}
				producer.Close();
			} catch (...) { producer.SetError(); }
		}).detach();

		return producer.Consumer();
	}

	template<typename DecryptorT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool DecryptAsymmetric(std::span<const std::byte> encryptedSpan, KeyPair::Generic::PointerType keypair, WriteOnly& output) noexcept {
		if (!keypair || !keypair->PrivateKey().has_value()) return false;
		try {
			// Deserialize and validate the private key
			auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(keypair->PrivateKey());
			if (!keyRes) return false;
			PrivateKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3)) return false;

			// Perform pure asymmetric decryption of the provided span
			DecryptorT pkDecryptor(key);
			DataType decryptedData;
			CryptoPP::PK_DecryptorFilter pkdf(RNG(), pkDecryptor, new CryptoPP::StringSinkTemplate<DataType>(decryptedData));
			pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(encryptedSpan.data()), encryptedSpan.size_bytes());
			pkdf.MessageEnd();
			return output.Write(std::move(decryptedData));
		} catch (...) { return false; }
	}

	template<typename DecryptorT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer DecryptAsymmetric(Consumer consumer, KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		Producer producer;
		if (!keypair || !keypair->PrivateKey().has_value()) {
			producer.SetError();
			return producer.Consumer();
		}

		std::thread([consumer, producer, keypair, mode]() mutable {
			try {
				if (!keypair || !keypair->PrivateKey().has_value()) { producer.SetError(); return; }
				auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(keypair->PrivateKey().value());
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

					// Decrypt this chunk with PK
					DecryptorT pkDecryptor(key);
					DataType decryptedChunk;
					CryptoPP::PK_DecryptorFilter pkdf(RNG(), pkDecryptor, new CryptoPP::StringSinkTemplate<DataType>(decryptedChunk));
					pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
					pkdf.MessageEnd();

					if (!producer.Write(std::move(decryptedChunk))) { producer.SetError(); return; }
				}
				producer.Close();
			} catch (...) { producer.SetError(); }
		}).detach();

		return producer.Consumer();
	}

		// Decrypt block: expect header (4-byte big-endian esk_len, esk bytes, IV) + payload
		template<typename DecryptorT, typename PrivateKeyT>
		STORMBYTE_CRYPTO_PRIVATE bool DecryptAsymmetricBlockEnvelope(std::span<const std::byte> encryptedSpan, KeyPair::Generic::PointerType keypair, WriteOnly& output) noexcept {
			try {
				if (!keypair || !keypair->PrivateKey().has_value()) return false;

				// Need at least 4 bytes for header
				if (encryptedSpan.size_bytes() < 4) return false;

				// Read esk_len
				uint32_t esk_len = (static_cast<uint32_t>(encryptedSpan[0]) << 24) |
								   (static_cast<uint32_t>(encryptedSpan[1]) << 16) |
								   (static_cast<uint32_t>(encryptedSpan[2]) << 8) |
								   (static_cast<uint32_t>(encryptedSpan[3]));

				size_t pos = 4;
				if (encryptedSpan.size_bytes() < pos + esk_len + 12) return false; // 12 == ivLen

				DataType eskData(esk_len);
				std::memcpy(eskData.data(), encryptedSpan.data() + pos, esk_len);
				pos += esk_len;

				constexpr size_t ivLen = 12;
				CryptoPP::SecByteBlock iv(ivLen);
				std::memcpy(iv.data(), encryptedSpan.data() + pos, ivLen);
				pos += ivLen;

				// Decrypt encryptedSymKey using private key
				auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(keypair->PrivateKey());
				if (!keyRes) return false;
				PrivateKeyT priv = std::move(*keyRes);
				if (!priv.Validate(RNG(), 3)) return false;

				DecryptorT pkDecryptor(priv);
				DataType symKeyData;
				{
					CryptoPP::PK_DecryptorFilter pkdf(RNG(), pkDecryptor, new CryptoPP::StringSinkTemplate<DataType>(symKeyData));
					pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(eskData.data()), eskData.size());
					pkdf.MessageEnd();
				}

				if (symKeyData.empty()) return false;
				CryptoPP::SecByteBlock symKey(reinterpret_cast<const CryptoPP::byte*>(symKeyData.data()), symKeyData.size());

				// Payload starts at pos
				size_t payloadLen = encryptedSpan.size_bytes() - pos;
				const CryptoPP::byte* payloadPtr = reinterpret_cast<const CryptoPP::byte*>(encryptedSpan.data() + pos);

				// Decrypt payload with AES-GCM
				CryptoPP::GCM<CryptoPP::AES>::Decryption aead;
				aead.SetKeyWithIV(symKey, symKey.size(), iv, ivLen);

				DataType out;
				CryptoPP::StreamTransformationFilter stf(aead, new CryptoPP::StringSinkTemplate<DataType>(out));
				if (payloadLen > 0) stf.Put(payloadPtr, payloadLen);
				stf.MessageEnd();

				return output.Write(std::move(out));
			} catch (...) {
				return false;
			}
		}
}