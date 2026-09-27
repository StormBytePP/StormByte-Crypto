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

#include <StormByte/crypto/engine/hasher/details.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filters.h>
#include <hex.h>
#include <memory>
#include <secblock.h>
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
				 * @brief One-shot hash. Builds Ops and delegates.
				 * @tparam HasherT Crypto++ hash type.
				 * @param dataSpan Input.
				 * @param output Hex digest destination.
				 * @return true on success.
				 */
				template<class HasherT>
				STORMBYTE_CRYPTO_PRIVATE bool Hash(std::span<const std::byte> dataSpan, Buffer::WriteOnly& output) noexcept {
					struct ConcreteOps final : Ops {
						HasherT hash;

						void Update(std::span<const std::byte> in) override {
							hash.Update(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
						}

						bool Finalize(StormByte::BinaryData& out) override {
							try {
								const size_t digestSize = hash.DigestSize();
								CryptoPP::SecByteBlock digest(digestSize);
								hash.Final(digest);

								CryptoPP::HexEncoder encoder(
									new CryptoPP::StringSinkTemplate<StormByte::BinaryData>(out)
								);
								encoder.Put(digest, digestSize);
								encoder.MessageEnd();
								return true;
							} catch (...) {
								return false;
							}
						}
					};

					return ProcessSpan(dataSpan, output, std::make_unique<ConcreteOps>());
				}

				/**
				 * @brief Streaming hash. Builds Ops and delegates.
				 * @tparam HasherT Crypto++ hash type.
				 * @param consumer Input consumer.
				 * @param mode Copy or move.
				 * @return Consumer with the hex digest.
				 */
				template<class HasherT>
				STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Hash(Buffer::Consumer consumer, ReadMode mode) noexcept {
					struct ConcreteOps final : Ops {
						HasherT hash;

						void Update(std::span<const std::byte> in) override {
							hash.Update(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
						}

						bool Finalize(StormByte::BinaryData& out) override {
							try {
								const size_t digestSize = hash.DigestSize();
								CryptoPP::SecByteBlock digest(digestSize);
								hash.Final(digest);

								CryptoPP::HexEncoder encoder(
									new CryptoPP::StringSinkTemplate<StormByte::BinaryData>(out)
								);
								encoder.Put(digest, digestSize);
								encoder.MessageEnd();
								return true;
							} catch (...) {
								return false;
							}
						}
					};

					return Stream(std::move(consumer), mode, std::make_unique<ConcreteOps>());
				}
			}
		}
	}
}
