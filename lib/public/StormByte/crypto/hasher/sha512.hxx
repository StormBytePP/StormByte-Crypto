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

#include <StormByte/crypto/hasher/generic.hxx>

/**
 * @namespace Hasher
 * @brief The namespace containing all the hasher-related classes.
 */
namespace StormByte::Crypto::Hasher {
	/**
	 * @class SHA512
	 * @brief A SHA512 hasher class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SHA512 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 */
			inline SHA512():
				Generic(Type::SHA512) {}

			/**
			 * @brief Copy constructor
			 * @param other The other SHA512 hasher to copy from.
			 */
			SHA512(const SHA512& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other SHA512 hasher to move from.
			 */
			SHA512(SHA512&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~SHA512() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other SHA512 hasher to copy from.
			 * @return Reference to this SHA512 hasher.
			 */
			SHA512& operator=(const SHA512& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other SHA512 hasher to move from.
			 * @return Reference to this SHA512 hasher.
			 */
			SHA512& operator=(SHA512&& other) noexcept = default;

			/**
			 * @brief Clone the SHA512 hasher.
			 * @return A pointer to the cloned SHA512 hasher.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<SHA512>(*this);
			}

			/**
			 * @brief Move the SHA512 hasher.
			 * @return A pointer to the moved SHA512 hasher.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<SHA512>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the hashing logic.
			 * @param input The input buffer to hash.
			 * @param output The output buffer to write the hashed data to.
			 * @return true if hashing was successful, false otherwise.
			 */
			bool DoHash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the hashing logic for Consumer buffers.
			 * @param consumer The Consumer buffer to hash.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the hashed data.
			 */
			Buffer::Consumer DoHash(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}
