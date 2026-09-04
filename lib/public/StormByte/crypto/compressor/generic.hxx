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
 * @brief Compressors of the Crypto module.
 */
namespace StormByte::Crypto::Compressor {
	/**
	 * @enum Type
	 * @brief Available compressors.
	 */
	enum class Type {
		Bzip2,	///< bzip2
		Zlib	///< zlib
	};

	/**
	 * @class Generic
	 * @brief Abstract compressor. Concrete codecs derive from this.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Compressor to copy.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Compressor to move.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Compressor to copy.
			 * @return Reference to this compressor.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Compressor to move.
			 * @return Reference to this compressor.
			 */
			Generic& operator=(Generic&& other) noexcept = default;
			/** @} */

			/**
			 * @name Compress
			 * @{
			 */
			/**
			 * @brief Compress a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Compress(const std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoCompress(input, output);
			}

			/**
			 * @brief Compress a read-only buffer (copy).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Compress(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoCompress(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Compress a buffer, consuming it.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Compress(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoCompress(input, output, ReadMode::Move);
			}

			/**
			 * @brief Compress a Consumer into another Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with compressed data.
			 */
			inline Buffer::Consumer Compress(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoCompress(consumer, mode);
			}
			/** @} */

			/**
			 * @name Decompress
			 * @{
			 */
			/**
			 * @brief Decompress a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Decompress(const std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoDecompress(input, output);
			}

			/**
			 * @brief Decompress a read-only buffer (copy).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Decompress(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecompress(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Decompress a buffer, consuming it.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Decompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecompress(input, output, ReadMode::Move);
			}

			/**
			 * @brief Decompress a Consumer into another Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with decompressed data.
			 */
			inline Buffer::Consumer Decompress(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoDecompress(consumer, mode);
			}
			/** @} */

			/**
			 * @brief Compression level.
			 * @return Level.
			 */
			unsigned short Level() const noexcept {
				return m_level;
			}

			/**
			 * @brief Codec of this compressor.
			 * @return Compressor type.
			 */
			inline enum Type Type() const noexcept {
				return m_type;
			}

		protected:
			enum Type m_type;			///< Codec
			unsigned short m_level = 0;	///< Compression level

			/**
			 * @brief Construct with a codec and level.
			 * @param type Codec.
			 * @param level Compression level.
			 */
			inline Generic(enum Type type, unsigned short level = 5):
				m_type(type), m_level(level) {}

		private:
			/**
			 * @brief Compress a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			virtual bool DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Compress a buffer with an explicit read mode.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param mode Copy or move.
			 * @return true on success.
			 */
			bool DoCompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Compress a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with compressed data.
			 */
			virtual Buffer::Consumer DoCompress(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

			/**
			 * @brief Decompress a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			virtual bool DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Decompress a buffer with an explicit read mode.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param mode Copy or move.
			 * @return true on success.
			 */
			bool DoDecompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Decompress a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with decompressed data.
			 */
			virtual Buffer::Consumer DoDecompress(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;
	};

	/**
	 * @brief Factory for a compressor.
	 * @param type Codec.
	 * @param level Compression level.
	 * @return Compressor pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, unsigned short level) noexcept;
}
