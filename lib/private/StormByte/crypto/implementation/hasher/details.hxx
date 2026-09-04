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

#include <functional>
#include <memory>
#include <secblock.h>
#include <span>

/**
 * @brief Private hasher implementation.
 */
namespace StormByte::Crypto::Implementation::Hasher {
	/**
	 * @struct Ops
	 * @brief Chunk-oriented hash engine.
	 */
	struct Ops {
		virtual ~Ops() = default;

		/**
		 * @brief Feed one chunk.
		 * @param in Input bytes.
		 */
		virtual void Update(std::span<const std::byte> in) = 0;

		/**
		 * @brief Finish and write the hex digest.
		 * @param out Destination.
		 * @return true on success.
		 */
		virtual bool Finalize(Buffer::DataType& out) = 0;
	};

	/**
	 * @brief One-shot hash.
	 * @param data Input.
	 * @param output Destination.
	 * @param ops Engine.
	 * @return true on success.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool ProcessSpan(
		std::span<const std::byte> data,
		Buffer::WriteOnly& output,
		std::unique_ptr<Ops> ops) noexcept;

	/**
	 * @brief Streaming hash. Yields a hex digest.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param ops Engine.
	 * @return Consumer with the digest.
	 */
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Stream(
		Buffer::Consumer consumer,
		ReadMode mode,
		std::unique_ptr<Ops> ops) noexcept;
}
