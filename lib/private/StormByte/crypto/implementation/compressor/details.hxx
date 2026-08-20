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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <span>
#include <memory>

namespace StormByte::Crypto::Implementation::Compressor {
	/**
	 * @brief Type-erased chunk-oriented compress/decompress engine.
	 *
	 * Concrete boxes wrap bzlib, Crypto++ Zlib, or future algorithms.
	 * The streaming loop lives once in details.cxx.
	 */
	struct StreamOps {
		virtual ~StreamOps() = default;

		/**
		 * @brief Feed one input chunk and append produced bytes to @p out.
		 * @return true on success.
		 */
		virtual bool Process(std::span<const std::byte> in,
							Buffer::DataType& out) = 0;

		/**
		 * @brief Finish the stream and append remaining bytes to @p out.
		 * @return true on success.
		 */
		virtual bool Finalize(Buffer::DataType& out) = 0;
	};

	/**
	 * @brief One-shot: Process(all) + Finalize → write to @p output.
	 */
	bool ProcessSpan(std::span<const std::byte> data,
					Buffer::WriteOnly& output,
					std::unique_ptr<StreamOps> ops) noexcept;

	/**
	 * @brief Streaming compress/decompress.
	 */
	Buffer::Consumer Stream(Buffer::Consumer consumer,
							ReadMode mode,
							std::unique_ptr<StreamOps> ops) noexcept;
}
