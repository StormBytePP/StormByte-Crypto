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

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/clonable.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

/**
 * @brief Hash algorithms of the Crypto module.
 */
namespace StormByte::Crypto::Hasher {
	/**
	 * @enum Type
	 * @brief Available hash algorithms.
	 */
	enum class Type {
		Blake2b,	///< BLAKE2b
		Blake2s,	///< BLAKE2s
		SHA3_256,	///< SHA3-256
		SHA3_512,	///< SHA3-512
		SHA256,		///< SHA-256
		SHA512,		///< SHA-512
	};

	/**
	 * @class Generic
	 * @brief Abstract hasher. Concrete algorithms derive from this.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Hasher to copy.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Hasher to move.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Hasher to copy.
			 * @return Reference to this hasher.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Hasher to move.
			 * @return Reference to this hasher.
			 */
			Generic& operator=(Generic&& other) noexcept = default;
			/** @} */

			/**
			 * @name Hash
			 * @{
			 */
			/**
			 * @brief Hash a byte span into an output buffer.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Hash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoHash(input, output);
			}

			/**
			 * @brief Hash a read-only buffer (copy).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Hash(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoHash(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Hash a buffer, consuming it.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Hash(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoHash(input, output, ReadMode::Move);
			}

			/**
			 * @brief Hash a Consumer into another Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with the digest.
			 */
			inline Buffer::Consumer Hash(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoHash(consumer, mode);
			}

			/**
			 * @brief Algorithm of this hasher.
			 * @return Hasher type.
			 */
			inline enum Type Type() const noexcept {
				return m_type;
			}
			/** @} */

		protected:
			enum Type m_type;	///< Algorithm

			/**
			 * @brief Construct with an algorithm.
			 * @param type Algorithm.
			 */
			inline Generic(enum Type type):
				m_type(type) {}

		private:
			/**
			 * @brief Hash a buffer with an explicit read mode.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param mode Copy or move.
			 * @return true on success.
			 */
			bool DoHash(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Hash a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			virtual bool DoHash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Hash a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with the digest.
			 */
			virtual Buffer::Consumer DoHash(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;
	};

	/**
	 * @brief Factory for a hasher.
	 * @param type Algorithm.
	 * @return Hasher pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type) noexcept;
}
