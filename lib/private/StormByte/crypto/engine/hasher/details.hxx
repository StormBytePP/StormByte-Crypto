/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <memory>
#include <span>

/**
 * @namespace StormByte
 * @brief Root namespace of the StormByte suite.
 */
namespace StormByte {
	/**
	 * @namespace StormByte::Crypto
	 * @brief Crypto module of the StormByte suite.
	 */
	namespace Crypto {
		/**
		 * @namespace StormByte::Crypto::Implementation
		 * @brief Private implementation of the Crypto module.
		 */
		namespace Engine {
			/**
			 * @namespace StormByte::Crypto::Engine::Hasher
			 * @brief Private hasher implementation.
			 */
			namespace Hasher {
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
					virtual bool Finalize(StormByte::BinaryData& out) = 0;
				};

				/**
				 * @brief One-shot hash.
				 * @param data Input.
				 * @param output Destination.
				 * @param ops Engine.
				 * @return true on success.
				 */
				STORMBYTE_CRYPTO_PRIVATE bool ProcessSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, std::unique_ptr<Ops> ops) noexcept;

				/**
				 * @brief Streaming hash. Yields a hex digest.
				 * @param consumer Input consumer.
				 * @param mode Copy or move.
				 * @param ops Engine.
				 * @return Consumer with the digest.
				 */
				STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Stream(Buffer::Consumer consumer, ReadMode mode, std::unique_ptr<Ops> ops) noexcept;
			}
		}
	}
}
