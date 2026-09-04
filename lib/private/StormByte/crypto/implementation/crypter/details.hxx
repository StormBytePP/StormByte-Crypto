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
 * @brief Private crypter implementation.
 */
namespace StormByte::Crypto::Implementation::Crypter {
	/**
	 * @struct Ops
	 * @brief Chunk encrypt/decrypt engine (symmetric and asymmetric).
	 */
	struct Ops {
		virtual ~Ops() = default;

		/**
		 * @brief Optional header write (salt||IV, hybrid envelope).
		 * @param outChunk Destination.
		 * @return true on success.
		 */
		virtual bool WriteHeader(Buffer::DataType& outChunk)
		{
			outChunk.clear();
			return true;
		}

		/**
		 * @brief Optional header read from a span (one-shot decrypt).
		 * @param in Input; advanced past the header.
		 * @return true on success.
		 */
		virtual bool ReadHeader(std::span<const std::byte>& /*in*/)
		{
			return true;
		}

		/**
		 * @brief Optional header read from a Consumer (streaming decrypt).
		 * @param consumer Input consumer.
		 * @return true on success.
		 */
		virtual bool ReadHeader(Buffer::Consumer& /*consumer*/)
		{
			return true;
		}

		/**
		 * @brief Process one chunk.
		 * @param in Input bytes.
		 * @param outChunk Output chunk.
		 * @return true on success.
		 */
		virtual bool Process(std::span<const std::byte> in,
							Buffer::DataType& outChunk) = 0;

		/**
		 * @brief Finish and emit padding/tag.
		 * @param outChunk Output chunk.
		 * @return true on success.
		 */
		virtual bool Finalize(Buffer::DataType& outChunk) = 0;
	};

	/**
	 * @brief One-shot encrypt/decrypt.
	 * @param data Input.
	 * @param output Destination.
	 * @param ops Engine.
	 * @return true on success.
	 */
	bool ProcessSpan(
		std::span<const std::byte> data,
		Buffer::WriteOnly& output,
		std::unique_ptr<Ops> ops) noexcept;

	/**
	 * @brief Streaming encrypt/decrypt.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param ops Engine.
	 * @return Consumer with the result.
	 */
	Buffer::Consumer Stream(
		Buffer::Consumer consumer,
		ReadMode mode,
		std::unique_ptr<Ops> ops) noexcept;
}
