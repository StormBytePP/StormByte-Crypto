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

#include <StormByte/crypto/crypter/symmetric/generic.hxx>

/**
 * @brief Ciphers of the Crypto module.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class TwoFish
	 * @brief Twofish-CBC crypter.
	 */
	class STORMBYTE_CRYPTO_PUBLIC TwoFish final: public Symmetric {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct with a password.
			 * @param password Password.
			 */
			inline TwoFish(class Password password):
				Symmetric(Type::TwoFish, std::move(password)) {}

			/**
			 * @brief Copy constructor.
			 * @param other Crypter to copy.
			 */
			TwoFish(const TwoFish& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Crypter to move.
			 */
			TwoFish(TwoFish&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~TwoFish() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Crypter to copy.
			 * @return Reference to this crypter.
			 */
			TwoFish& operator=(const TwoFish& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Crypter to move.
			 * @return Reference to this crypter.
			 */
			TwoFish& operator=(TwoFish&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this crypter.
			 * @return Shared pointer to the clone.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<TwoFish>(*this);
			}

			/**
			 * @brief Move this crypter into a new instance.
			 * @return Shared pointer to the moved crypter.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<TwoFish>(std::move(*this));
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
