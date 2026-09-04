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

#include <span>
#include <memory>

namespace StormByte::Crypto::Implementation::Crypter {
	/**
	 * @brief Minimal interface for a chunk-oriented encrypt/decrypt operation.
	 *
	 * Supports both Symmetric and Asymmetric (native + hybrid) flows.
	 * Header write (encrypt) and header read (decrypt) are optional hooks.
	 */
	struct Ops {
		virtual ~Ops() = default;

		/**
		 * @brief Optional: write header bytes (salt||IV, hybrid envelope, …).
		 * Encrypt paths use this; decrypt paths leave @p outChunk empty.
		 */
		virtual bool WriteHeader(Buffer::DataType& outChunk)
		{
			outChunk.clear();
			return true;
		}

		/**
		 * @brief Optional: consume header from a span (decrypt one-shot).
		 * Advances @p in past the header.
		 */
		virtual bool ReadHeader(std::span<const std::byte>& /*in*/)
		{
			return true;
		}

		/**
		 * @brief Optional: consume header from a Consumer (decrypt streaming).
		 */
		virtual bool ReadHeader(Buffer::Consumer& /*consumer*/)
		{
			return true;
		}

		/**
		 * @brief Process one input chunk.
		 */
		virtual bool Process(std::span<const std::byte> in,
							Buffer::DataType& outChunk) = 0;

		/**
		 * @brief Finalize and emit remaining data (padding / tag / …).
		 */
		virtual bool Finalize(Buffer::DataType& outChunk) = 0;
	};

	bool ProcessSpan(
		std::span<const std::byte> data,
		Buffer::WriteOnly& output,
		std::unique_ptr<Ops> ops) noexcept;

	Buffer::Consumer Stream(
		Buffer::Consumer consumer,
		ReadMode mode,
		std::unique_ptr<Ops> ops) noexcept;
}
