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
	 * @class SHA3_256
	 * @brief A SHA3_256 hasher class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC SHA3_256 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 */
			inline SHA3_256():
				Generic(Type::SHA3_256) {}

			/**
			 * @brief Copy constructor
			 * @param other The other SHA3_256 hasher to copy from.
			 */
			SHA3_256(const SHA3_256& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other SHA3_256 hasher to move from.
			 */
			SHA3_256(SHA3_256&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~SHA3_256() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other SHA3_256 hasher to copy from.
			 * @return Reference to this SHA3_256 hasher.
			 */
			SHA3_256& operator=(const SHA3_256& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other SHA3_256 hasher to move from.
			 * @return Reference to this SHA3_256 hasher.
			 */
			SHA3_256& operator=(SHA3_256&& other) noexcept = default;

			/**
			 * @brief Clone the SHA3_256 hasher.
			 * @return A pointer to the cloned SHA3_256 hasher.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<SHA3_256>(*this);
			}

			/**
			 * @brief Move the SHA3_256 hasher.
			 * @return A pointer to the moved SHA3_256 hasher.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<SHA3_256>(std::move(*this));
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
