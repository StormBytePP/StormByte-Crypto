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

#include <StormByte/crypto/crypter/symmetric/generic.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class TwoFish
	 * @brief A symmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC TwoFish final: public Symmetric {
		public:
			/**
			 * @brief Constructor
			 * @param password The password used for encryption/decryption.
			 */
			inline TwoFish(class Password password):
				Symmetric(Type::TwoFish, std::move(password)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other TwoFish crypter to copy from.
			 */
			TwoFish(const TwoFish& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other TwoFish crypter to move from.
			 */
			TwoFish(TwoFish&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~TwoFish() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other TwoFish crypter to copy from.
			 * @return Reference to this TwoFish crypter.
			 */
			TwoFish& operator=(const TwoFish& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other TwoFish crypter to move from.
			 * @return Reference to this TwoFish crypter.
			 */
			TwoFish& operator=(TwoFish&& other) noexcept = default;

			/**
			 * @brief Clone the TwoFish crypter.
			 * @return A pointer to the cloned TwoFish crypter.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<TwoFish>(*this);
			}

			/**
			 * @brief Move the TwoFish crypter.
			 * @return A pointer to the moved TwoFish crypter.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<TwoFish>(std::move(*this));
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
