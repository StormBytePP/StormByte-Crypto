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
 * @namespace Hasher
 * @brief The namespace containing all the hasher-related classes.
 */
namespace StormByte::Crypto::Hasher {
	/**
	 * @class Blake2s
	 * @brief A Blake2s hasher class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Blake2s final: public Generic {
		public:
			/**
			 * @brief Constructor
			 */
			inline Blake2s():
				Generic(Type::Blake2s) {}

			/**
			 * @brief Copy constructor
			 * @param other The other Blake2s hasher to copy from.
			 */
			Blake2s(const Blake2s& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other Blake2s hasher to move from.
			 */
			Blake2s(Blake2s&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			~Blake2s() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Blake2s hasher to copy from.
			 * @return Reference to this Blake2s hasher.
			 */
			Blake2s& operator=(const Blake2s& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Blake2s hasher to move from.
			 * @return Reference to this Blake2s hasher.
			 */
			Blake2s& operator=(Blake2s&& other) noexcept = default;

			/**
			 * @brief Clone the Blake2s hasher.
			 * @return A pointer to the cloned Blake2s hasher.
			 */
			inline PointerType Clone() const noexcept override {
				return std::make_shared<Blake2s>(*this);
			}

			/**
			 * @brief Move the Blake2s hasher.
			 * @return A pointer to the moved Blake2s hasher.
			 */
			inline PointerType Move() noexcept override {
				return std::make_shared<Blake2s>(std::move(*this));
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
