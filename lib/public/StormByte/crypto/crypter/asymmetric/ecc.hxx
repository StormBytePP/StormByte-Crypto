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

#include <StormByte/crypto/crypter/asymmetric/generic.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class ECC
	 * @brief An asymmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECC final: public Asymmetric {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline ECC(KeyPair::Generic::PointerType keypair):
				Asymmetric(Type::ECC, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline ECC(const KeyPair::ECC& keypair):
				Asymmetric(Type::ECC, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline ECC(KeyPair::ECC&& keypair):
				Asymmetric(Type::ECC, std::forward<KeyPair::ECC>(keypair)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECC crypter to copy from.
			 */
			ECC(const ECC& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other ECC crypter to move from.
			 */
			ECC(ECC&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~ECC() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECC crypter to copy from.
			 * @return Reference to this ECC crypter.
			 */
			ECC& operator=(const ECC& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECC crypter to move from.
			 * @return Reference to this ECC crypter.
			 */
			ECC& operator=(ECC&& other) noexcept = default;

			/**
			 * @brief Clone the ECC crypter.
			 * @return A pointer to the cloned ECC crypter.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<ECC>(*this);
			}

			/**
			 * @brief Move the ECC crypter.
			 * @return A pointer to the moved ECC crypter.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<ECC>(std::move(*this));
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
