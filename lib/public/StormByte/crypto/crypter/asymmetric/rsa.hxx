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

#include <StormByte/crypto/crypter/asymmetric/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class RSA
	 * @brief An asymmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC RSA final: public Asymmetric {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline RSA(KeyPair::Generic::PointerType keypair):
				Asymmetric(Type::RSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline RSA(const KeyPair::RSA& keypair):
				Asymmetric(Type::RSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline RSA(KeyPair::RSA&& keypair):
				Asymmetric(Type::RSA, std::forward<KeyPair::RSA>(keypair)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other RSA crypter to copy from.
			 */
			RSA(const RSA& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other RSA crypter to move from.
			 */
			RSA(RSA&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~RSA() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other RSA crypter to copy from.
			 * @return Reference to this RSA crypter.
			 */
			RSA& operator=(const RSA& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other RSA crypter to move from.
			 * @return Reference to this RSA crypter.
			 */
			RSA& operator=(RSA&& other) noexcept = default;

			/**
			 * @brief Clone the RSA crypter.
			 * @return A pointer to the cloned RSA crypter.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<RSA>(*this);
			}

			/**
			 * @brief Move the RSA crypter.
			 * @return A pointer to the moved RSA crypter.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<RSA>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the encryption logic.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @return true if encryption was successful, false otherwise.
			 */
			bool DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the encryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to encrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			Buffer::Consumer DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Implementation of the decryption logic.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			bool DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the decryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to decrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			Buffer::Consumer DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}
