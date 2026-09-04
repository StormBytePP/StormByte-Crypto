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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <memory>
#include <span>

/**
 * @brief Private compressor implementation.
 */
namespace StormByte::Crypto::Implementation::Compressor {
	/**
	 * @struct StreamOps
	 * @brief Type-erased chunk compress/decompress engine.
	 */
	struct StreamOps {
		virtual ~StreamOps() = default;

		/**
		 * @brief Feed one chunk and append output.
		 * @param in Input bytes.
		 * @param out Accumulated output.
		 * @return true on success.
		 */
		virtual bool Process(std::span<const std::byte> in,
							Buffer::DataType& out) = 0;

		/**
		 * @brief Finish the stream and append remaining bytes.
		 * @param out Accumulated output.
		 * @return true on success.
		 */
		virtual bool Finalize(Buffer::DataType& out) = 0;
	};

	/**
	 * @brief One-shot Process + Finalize into a buffer.
	 * @param data Input.
	 * @param output Destination.
	 * @param ops Engine.
	 * @return true on success.
	 */
	bool ProcessSpan(std::span<const std::byte> data,
					Buffer::WriteOnly& output,
					std::unique_ptr<StreamOps> ops) noexcept;

	/**
	 * @brief Streaming compress/decompress.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param ops Engine.
	 * @return Consumer with the result.
	 */
	Buffer::Consumer Stream(Buffer::Consumer consumer,
							ReadMode mode,
							std::unique_ptr<StreamOps> ops) noexcept;
}
