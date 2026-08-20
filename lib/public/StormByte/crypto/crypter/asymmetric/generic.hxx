/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte.
 *
 * StormByte is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * StormByte is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <StormByte/crypto/crypter/generic.hxx>
#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class Asymmetric
	 * @brief A generic asymmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Asymmetric: public Generic {
		public:
			/**
			 * @enum Strategy
			 * @brief Encryption strategy for asymmetric crypters.
			 *
			 * Defines whether to use pure asymmetric encryption or a hybrid envelope
			 * (asymmetric key encapsulation + AES-GCM).
			 */
			enum class Strategy {
				Hybrid,		///< Hybrid envelope: encrypts a random symmetric key with the public key and the data with AES-GCM
				Native,		///< Native/pure asymmetric encryption (no hybrid layer)
			};

			/**
			 * @brief Copy constructor
			 * @param other The other Asymmetric crypter to copy from.
			 */
			Asymmetric(const Asymmetric& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other Asymmetric crypter to move from.
			 */
			Asymmetric(Asymmetric&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Asymmetric() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Asymmetric crypter to copy from.
			 * @return Reference to this Asymmetric crypter.
			 */
			Asymmetric& operator=(const Asymmetric& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Asymmetric crypter to move from.
			 * @return Reference to this Asymmetric crypter.
			 */
			Asymmetric& operator=(Asymmetric&& other) noexcept = default;

			/**
			 * @brief Gets the keypair used for asymmetric encryption.
			 * @return The keypair.
			 */
			KeyPair::Generic::PointerType KeyPair() const noexcept {
				return m_keypair;
			}

			/**
			 * @brief Encrypt data using the specified strategy.
			 * @param input The input data to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @param strategy The encryption strategy (Native or Hybrid). Defaults to Native.
			 * @return true if encryption was successful, false otherwise.
			 */
			bool Encrypt(std::span<const std::byte> input, Buffer::WriteOnly& output, Strategy strategy = Strategy::Native) const noexcept;

			/**
			 * @brief Encrypt data using the specified strategy.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @param strategy The encryption strategy (Native or Hybrid). Defaults to Native.
			 * @return true if encryption was successful, false otherwise.
			 */
			bool Encrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output, Strategy strategy = Strategy::Native) const noexcept;

			/**
			 * @brief Encrypt data using the specified strategy (moves the input).
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @param strategy The encryption strategy (Native or Hybrid). Defaults to Native.
			 * @return true if encryption was successful, false otherwise.
			 */
			bool Encrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, Strategy strategy = Strategy::Native) const noexcept;

			/**
			 * @brief Encrypt data from a Consumer using the specified strategy.
			 * @param consumer The Consumer buffer to encrypt.
			 * @param strategy The encryption strategy (Native or Hybrid). Defaults to Native.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			Buffer::Consumer Encrypt(Buffer::Consumer consumer, Strategy strategy = Strategy::Native, ReadMode mode = ReadMode::Move) const noexcept;

			/**
			 * @brief Decrypt data. Automatically detects whether the data is Native or Hybrid.
			 * @param input The input data to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			bool Decrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept;

			/**
			 * @brief Decrypt data. Automatically detects whether the data is Native or Hybrid.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			bool Decrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept;

			/**
			 * @brief Decrypt data (moves the input). Automatically detects whether the data is Native or Hybrid.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			bool Decrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept;

			/**
			 * @brief Decrypt data from a Consumer. Automatically detects whether the data is Native or Hybrid.
			 * @param consumer The Consumer buffer to decrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			Buffer::Consumer Decrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept;

		protected:
			KeyPair::Generic::PointerType m_keypair;	///< The keypair used for asymmetric encryption

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline Asymmetric(enum Type type, KeyPair::Generic::PointerType keypair):
				Generic(type), m_keypair(keypair) {}

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline Asymmetric(enum Type type, const KeyPair::Generic& keypair):
				Generic(type), m_keypair(keypair.Clone()) {}

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline Asymmetric(enum Type type, KeyPair::Generic&& keypair):
				Generic(type), m_keypair(keypair.Move()) {}
	};

	/**
	 * @brief Creates an Asymmetric crypter of the specified type using the provided keypair.
	 * @param type The type of crypter to create.
	 * @param keypair The keypair to use for the crypter.
	 * @return A pointer to the created Asymmetric crypter.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept;

	/**
	 * @brief Creates an Asymmetric crypter of the specified type using the provided keypair.
	 * @param type The type of crypter to create.
	 * @param keypair The keypair to use for the crypter.
	 * @return A pointer to the created Asymmetric crypter.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, const KeyPair::Generic& keypair) noexcept;

	/**
	 * @brief Creates an Asymmetric crypter of the specified type using the provided keypair.
	 * @param type The type of crypter to create.
	 * @param keypair The keypair to use for the crypter.
	 * @return A pointer to the created Asymmetric crypter.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic&& keypair) noexcept;
}
