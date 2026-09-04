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

#pragma once

#include <StormByte/crypto/implementation/crypter/asymmetric/details.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filters.h>
#include <memory>
#include <span>

/**
 * @brief Private asymmetric crypter implementation.
 */
namespace StormByte::Crypto::Implementation::Crypter::Asymmetric {
	namespace {
		/**
		 * @struct EncryptBox
		 * @brief Public-key encryptor as PkBox.
		 * @tparam CryptorT Crypto++ encryptor type.
		 * @tparam KeyT Crypto++ public key type.
		 */
		template<typename CryptorT, typename KeyT>
		struct EncryptBox final : PkBox {
			std::unique_ptr<KeyT> key;	///< Loaded public key

			/**
			 * @brief Load the public key from a KeyPair.
			 * @param keypair Key pair.
			 */
			explicit EncryptBox(StormByte::Crypto::KeyPair::Generic::PointerType keypair)
			{
				if (!keypair)
					return;
				auto keyRes = KeyPair::DeserializeKey<KeyT>(keypair->PublicKey());
				if (!keyRes)
					return;
				key = std::make_unique<KeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3))
					key.reset();
			}

			/**
			 * @brief Encrypt one blob.
			 * @param in Input.
			 * @param out Destination.
			 * @return true on success.
			 */
			bool Transform(std::span<const std::byte> in, Buffer::DataType& out) override
			{
				if (!key)
					return false;
				try {
					CryptorT encryptor(*key);
					CryptoPP::PK_EncryptorFilter pkf(
						RNG(), encryptor,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
					);
					pkf.Put(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
					pkf.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		/**
		 * @struct DecryptBox
		 * @brief Private-key decryptor as PkBox.
		 * @tparam DecryptorT Crypto++ decryptor type.
		 * @tparam KeyT Crypto++ private key type.
		 */
		template<typename DecryptorT, typename KeyT>
		struct DecryptBox final : PkBox {
			std::unique_ptr<KeyT> key;	///< Loaded private key

			/**
			 * @brief Load the private key from a KeyPair.
			 * @param keypair Key pair with private key.
			 */
			explicit DecryptBox(StormByte::Crypto::KeyPair::Generic::PointerType keypair)
			{
				if (!keypair || !keypair->HasPrivateKey())
					return;
				auto keyRes = KeyPair::DeserializeKey<KeyT>(*keypair->PrivateKey());
				if (!keyRes)
					return;
				key = std::make_unique<KeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3))
					key.reset();
			}

			/**
			 * @brief Load the private key from a Password.
			 * @param privKey DER private key.
			 */
			explicit DecryptBox(const Password& privKey)
			{
				auto keyRes = KeyPair::DeserializeKey<KeyT>(privKey);
				if (!keyRes)
					return;
				key = std::make_unique<KeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3))
					key.reset();
			}

			/**
			 * @brief Decrypt one blob.
			 * @param in Input.
			 * @param out Destination.
			 * @return true on success.
			 */
			bool Transform(std::span<const std::byte> in, Buffer::DataType& out) override
			{
				if (!key)
					return false;
				try {
					DecryptorT decryptor(*key);
					CryptoPP::PK_DecryptorFilter pkdf(
						RNG(), decryptor,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
					);
					pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
					pkdf.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

	}

	/**
	 * @brief Native one-shot encrypt.
	 * @tparam CryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param data Input.
	 * @param keypair Key pair.
	 * @param output Destination.
	 * @return true on success.
	 */
	template<typename CryptorT, typename PublicKeyT>
	bool EncryptAsymmetric(std::span<const std::byte> data,
						StormByte::Crypto::KeyPair::Generic::PointerType keypair,
						Buffer::WriteOnly& output) noexcept
	{
		return NativeProcessSpan(
			data, output,
			std::make_unique<EncryptBox<CryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Native streaming encrypt.
	 * @tparam CryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param consumer Input consumer.
	 * @param keypair Key pair.
	 * @param mode Copy or move.
	 * @return Consumer with the ciphertext.
	 */
	template<typename CryptorT, typename PublicKeyT>
	Buffer::Consumer EncryptAsymmetric(Buffer::Consumer consumer,
									StormByte::Crypto::KeyPair::Generic::PointerType keypair,
									ReadMode mode) noexcept
	{
		return NativeProcessStream(
			std::move(consumer), mode,
			std::make_unique<EncryptBox<CryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Hybrid one-shot encrypt (AES-GCM + PK-wrapped session key).
	 * @tparam EncryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param data Input.
	 * @param keypair Key pair.
	 * @param output Destination.
	 * @return true on success.
	 */
	template<typename EncryptorT, typename PublicKeyT>
	bool EncryptAsymmetricBlockEnvelope(std::span<const std::byte> data,
										StormByte::Crypto::KeyPair::Generic::PointerType keypair,
										Buffer::WriteOnly& output) noexcept
	{
		return HybridEncryptSpan(
			data, output,
			std::make_unique<EncryptBox<EncryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Hybrid streaming encrypt.
	 * @tparam EncryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param consumer Input consumer.
	 * @param keypair Key pair.
	 * @param mode Copy or move.
	 * @return Consumer with the envelope.
	 */
	template<typename EncryptorT, typename PublicKeyT>
	Buffer::Consumer EncryptAsymmetricBlockEnvelope(Buffer::Consumer consumer,
													StormByte::Crypto::KeyPair::Generic::PointerType keypair,
													ReadMode mode) noexcept
	{
		return HybridEncryptStream(
			std::move(consumer), mode,
			std::make_unique<EncryptBox<EncryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Native one-shot decrypt.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param data Input.
	 * @param keypair Key pair with private key.
	 * @param output Destination.
	 * @return true on success.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	bool DecryptAsymmetric(std::span<const std::byte> data,
						StormByte::Crypto::KeyPair::Generic::PointerType keypair,
						Buffer::WriteOnly& output) noexcept
	{
		return NativeProcessSpan(
			data, output,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Native streaming decrypt.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param consumer Input consumer.
	 * @param keypair Key pair with private key.
	 * @param mode Copy or move.
	 * @return Consumer with the plaintext, or error if no private key.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	Buffer::Consumer DecryptAsymmetric(Buffer::Consumer consumer,
									StormByte::Crypto::KeyPair::Generic::PointerType keypair,
									ReadMode mode) noexcept
	{
		if (!keypair || !keypair->HasPrivateKey()) {
			Buffer::Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return NativeProcessStream(
			std::move(consumer), mode,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(*keypair->PrivateKey()));
	}

	/**
	 * @brief Hybrid one-shot decrypt.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param data Input.
	 * @param keypair Key pair with private key.
	 * @param output Destination.
	 * @return true on success.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	bool DecryptAsymmetricBlockEnvelope(std::span<const std::byte> data,
										StormByte::Crypto::KeyPair::Generic::PointerType keypair,
										Buffer::WriteOnly& output) noexcept
	{
		return HybridDecryptSpan(
			data, output,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Hybrid streaming decrypt.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param consumer Input consumer.
	 * @param keypair Key pair with private key.
	 * @param mode Copy or move.
	 * @return Consumer with the plaintext, or error if no private key.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	Buffer::Consumer DecryptAsymmetricBlockEnvelope(Buffer::Consumer consumer,
													StormByte::Crypto::KeyPair::Generic::PointerType keypair,
													ReadMode mode) noexcept
	{
		if (!keypair || !keypair->HasPrivateKey()) {
			Buffer::Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return HybridDecryptStream(
			std::move(consumer), mode,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(*keypair->PrivateKey()));
	}
}
