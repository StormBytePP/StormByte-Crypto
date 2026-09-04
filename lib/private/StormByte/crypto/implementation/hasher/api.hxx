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

#include <StormByte/crypto/implementation/hasher/details.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filters.h>
#include <hex.h>
#include <memory>
#include <secblock.h>
#include <span>

/**
 * @brief Private hasher implementation.
 */
namespace StormByte::Crypto::Implementation::Hasher {
	/**
	 * @brief One-shot hash. Builds Ops and delegates.
	 * @tparam HasherT Crypto++ hash type.
	 * @param dataSpan Input.
	 * @param output Hex digest destination.
	 * @return true on success.
	 */
	template<class HasherT>
	STORMBYTE_CRYPTO_PRIVATE bool Hash(
		std::span<const std::byte> dataSpan,
		Buffer::WriteOnly& output) noexcept
	{
		struct ConcreteOps final : Ops {
			HasherT hash;

			void Update(std::span<const std::byte> in) override
			{
				hash.Update(
					reinterpret_cast<const CryptoPP::byte*>(in.data()),
					in.size_bytes());
			}

			bool Finalize(Buffer::DataType& out) override
			{
				try {
					const size_t digestSize = hash.DigestSize();
					CryptoPP::SecByteBlock digest(digestSize);
					hash.Final(digest);

					CryptoPP::HexEncoder encoder(
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
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
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Hash(
		Buffer::Consumer consumer,
		ReadMode mode) noexcept
	{
		struct ConcreteOps final : Ops {
			HasherT hash;

			void Update(std::span<const std::byte> in) override
			{
				hash.Update(
					reinterpret_cast<const CryptoPP::byte*>(in.data()),
					in.size_bytes());
			}

			bool Finalize(Buffer::DataType& out) override
			{
				try {
					const size_t digestSize = hash.DigestSize();
					CryptoPP::SecByteBlock digest(digestSize);
					hash.Final(digest);

					CryptoPP::HexEncoder encoder(
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
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
