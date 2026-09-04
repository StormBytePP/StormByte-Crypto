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

#include <StormByte/crypto/hasher/generic.hxx>

/**
 * @brief Hash algorithms of the Crypto module.
 */
namespace StormByte::Crypto::Hasher {
	/**
	 * @class SHA512
	 * @brief SHA-512 hasher.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SHA512 final: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Default constructor.
			 */
			inline SHA512():
				Generic(Type::SHA512) {}

			/**
			 * @brief Copy constructor.
			 * @param other Hasher to copy.
			 */
			SHA512(const SHA512& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Hasher to move.
			 */
			SHA512(SHA512&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~SHA512() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Hasher to copy.
			 * @return Reference to this hasher.
			 */
			SHA512& operator=(const SHA512& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Hasher to move.
			 * @return Reference to this hasher.
			 */
			SHA512& operator=(SHA512&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this hasher.
			 * @return Shared pointer to the clone.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<SHA512>(*this);
			}

			/**
			 * @brief Move this hasher into a new instance.
			 * @return Shared pointer to the moved hasher.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<SHA512>(std::move(*this));
			}

		private:
			/**
			 * @brief Hash a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool DoHash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Hash a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with the digest.
			 */
			Buffer::Consumer DoHash(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}
