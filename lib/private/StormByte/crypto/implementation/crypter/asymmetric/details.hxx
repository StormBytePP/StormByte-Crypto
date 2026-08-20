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

#include <StormByte/crypto/implementation/crypter/details.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <secblock.h>
#include <span>
#include <memory>
#include <cstdint>
#include <cstddef>

namespace StormByte::Crypto::Implementation::Crypter::Asymmetric {
	/** @brief AES-256 key length used in hybrid envelopes. */
	inline constexpr std::size_t kSymKeyLen = 32;

	/** @brief GCM IV length used in hybrid envelopes. */
	inline constexpr std::size_t kIvLen = 12;

	/**
	 * @brief Type-erased public/private key transform (encrypt or decrypt).
	 *
	 * Concrete implementations wrap a Crypto++ PK encryptor/decryptor.
	 * All hybrid and native helpers below only depend on this interface.
	 */
	struct PkBox {
		virtual ~PkBox() = default;

		/**
		 * @brief Transform raw bytes with the asymmetric key.
		 * @param in  Input bytes.
		 * @param out Destination for the result.
		 * @return true on success.
		 */
		virtual bool Transform(std::span<const std::byte> in,
							Buffer::DataType& out) = 0;
	};

	/**
	 * @brief Write hybrid envelope header: eskLen(4 BE) || esk || iv.
	 */
	bool WriteEnvelopeHeader(const Buffer::DataType& esk,
							const CryptoPP::SecByteBlock& iv,
							Buffer::DataType& out) noexcept;

	/**
	 * @brief Parse eskLen (4 bytes, big-endian).
	 * @return Length, or 0 if @p lenBytes is not exactly 4 bytes.
	 */
	std::uint32_t ParseEskLength(const Buffer::DataType& lenBytes) noexcept;

	// -------------------------------------------------------------------------
	// Native (each call / each stream chunk = one full PK transform)
	// -------------------------------------------------------------------------

	/**
	 * @brief One-shot native asymmetric encrypt/decrypt.
	 */
	bool NativeProcessSpan(std::span<const std::byte> data,
						Buffer::WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief Streaming native asymmetric encrypt/decrypt.
	 * Each chunk is transformed independently.
	 */
	Buffer::Consumer NativeProcessStream(Buffer::Consumer consumer,
										ReadMode mode,
										std::unique_ptr<PkBox> box) noexcept;

	// -------------------------------------------------------------------------
	// Hybrid envelope (AES-GCM + PK-wrapped session key)
	// -------------------------------------------------------------------------

	/**
	 * @brief One-shot hybrid envelope encryption.
	 * @param box Must encrypt the raw session key (public-key encrypt).
	 */
	bool HybridEncryptSpan(std::span<const std::byte> data,
						Buffer::WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief Streaming hybrid envelope encryption.
	 */
	Buffer::Consumer HybridEncryptStream(Buffer::Consumer consumer,
										ReadMode mode,
										std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief One-shot hybrid envelope decryption.
	 * @param box Must decrypt the encrypted session key (private-key decrypt).
	 */
	bool HybridDecryptSpan(std::span<const std::byte> data,
						Buffer::WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief Streaming hybrid envelope decryption.
	 */
	Buffer::Consumer HybridDecryptStream(Buffer::Consumer consumer,
										ReadMode mode,
										std::unique_ptr<PkBox> box) noexcept;
}
