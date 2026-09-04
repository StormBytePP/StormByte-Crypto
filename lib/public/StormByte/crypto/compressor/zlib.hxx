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

#include <StormByte/crypto/compressor/generic.hxx>

/**
 * @brief Compressors of the Crypto module.
 */
namespace StormByte::Crypto::Compressor {
	/**
	 * @class Zlib
	 * @brief zlib compressor.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Zlib final: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct with a compression level.
			 * @param level Compression level.
			 */
			Zlib(unsigned short level = 5);

			/**
			 * @brief Copy constructor.
			 * @param other Compressor to copy.
			 */
			Zlib(const Zlib& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Compressor to move.
			 */
			Zlib(Zlib&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~Zlib() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Compressor to copy.
			 * @return Reference to this compressor.
			 */
			Zlib& operator=(const Zlib& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Compressor to move.
			 * @return Reference to this compressor.
			 */
			Zlib& operator=(Zlib&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this compressor.
			 * @return Unique pointer to the clone.
			 */
			inline PointerType Clone() const override {
				return std::make_unique<Zlib>(*this);
			}

			/**
			 * @brief Move this compressor into a new instance.
			 * @return Unique pointer to the moved compressor.
			 */
			inline PointerType Move() noexcept override {
				return std::make_unique<Zlib>(std::move(*this));
			}

		private:
			/**
			 * @brief Compress a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Compress a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with compressed data.
			 */
			Buffer::Consumer DoCompress(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Decompress a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Decompress a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with decompressed data.
			 */
			Buffer::Consumer DoDecompress(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}
