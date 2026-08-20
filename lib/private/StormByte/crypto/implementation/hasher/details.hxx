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

#include <secblock.h>
#include <span>
#include <memory>
#include <functional>

namespace StormByte::Crypto::Implementation::Hasher {
	/**
	 * @brief Minimal interface for a chunk-oriented hash operation.
	 *
	 * Concrete implementations wrap a Crypto++ hash object.
	 * The heavy streaming loop lives in the non-templated helpers below.
	 */
	struct Ops {
		virtual ~Ops() = default;

		/**
		 * @brief Feed one input chunk into the hash.
		 * @param in Input data.
		 */
		virtual void Update(std::span<const std::byte> in) = 0;

		/**
		 * @brief Finalize the hash and write the hex-encoded digest into @p out.
		 * @param out Destination for the hex-encoded result.
		 * @return true on success, false on failure.
		 */
		virtual bool Finalize(Buffer::DataType& out) = 0;
	};

	/**
	 * @brief One-shot (span) hash helper.
	 *
	 * Calls Update + Finalize and writes the result to @p output.
	 *
	 * @param data     Input data.
	 * @param output   Destination buffer.
	 * @param ops      Ownership of the concrete hash operation.
	 * @return true on success, false on failure.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool ProcessSpan(
		std::span<const std::byte> data,
		Buffer::WriteOnly& output,
		std::unique_ptr<Ops> ops) noexcept;

	/**
	 * @brief Streaming hash helper.
	 *
	 * Runs the classic AvailableBytes / yield / Read|Extract loop in a
	 * detached thread and returns a Consumer that yields the hex-encoded digest.
	 *
	 * @param consumer Source of input data.
	 * @param mode     Copy or Move semantics.
	 * @param ops      Ownership of the concrete hash operation.
	 * @return Consumer that produces the final hex digest (or error).
	 */
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Stream(
		Buffer::Consumer consumer,
		ReadMode mode,
		std::unique_ptr<Ops> ops) noexcept;
}
