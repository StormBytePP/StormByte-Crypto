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
 * @brief Ciphers of the Crypto module.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class ECC
	 * @brief Elliptic-curve crypter.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECC final: public Asymmetric {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct from a keypair pointer.
			 * @param keypair Keypair.
			 */
			inline ECC(KeyPair::Generic::PointerType keypair):
				Asymmetric(Type::ECC, keypair) {}

			/**
			 * @brief Construct by cloning an ECC keypair.
			 * @param keypair Keypair.
			 */
			inline ECC(const KeyPair::ECC& keypair):
				Asymmetric(Type::ECC, keypair) {}

			/**
			 * @brief Construct by moving an ECC keypair.
			 * @param keypair Keypair.
			 */
			inline ECC(KeyPair::ECC&& keypair):
				Asymmetric(Type::ECC, std::forward<KeyPair::ECC>(keypair)) {}

			/**
			 * @brief Copy constructor.
			 * @param other Crypter to copy.
			 */
			ECC(const ECC& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Crypter to move.
			 */
			ECC(ECC&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~ECC() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Crypter to copy.
			 * @return Reference to this crypter.
			 */
			ECC& operator=(const ECC& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Crypter to move.
			 * @return Reference to this crypter.
			 */
			ECC& operator=(ECC&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this crypter.
			 * @return Shared pointer to the clone.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<ECC>(*this);
			}

			/**
			 * @brief Move this crypter into a new instance.
			 * @return Shared pointer to the moved crypter.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<ECC>(std::move(*this));
			}

		private:
			/**
			 * @brief Encrypt a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Encrypt a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with ciphertext.
			 */
			Buffer::Consumer DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Decrypt a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Decrypt a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with plaintext.
			 */
			Buffer::Consumer DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}
