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

#include <StormByte/crypto/implementation/crypter/details.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <secblock.h>
#include <span>

/**
 * @brief Private asymmetric crypter implementation.
 */
namespace StormByte::Crypto::Implementation::Crypter::Asymmetric {
	inline constexpr std::size_t kSymKeyLen = 32;	///< AES-256 key in hybrid envelopes
	inline constexpr std::size_t kIvLen = 12;		///< GCM IV in hybrid envelopes

	/**
	 * @struct PkBox
	 * @brief Type-erased public/private transform.
	 */
	struct PkBox {
		virtual ~PkBox() = default;

		/**
		 * @brief Transform raw bytes with the key.
		 * @param in Input.
		 * @param out Destination.
		 * @return true on success.
		 */
		virtual bool Transform(std::span<const std::byte> in,
							Buffer::DataType& out) = 0;
	};

	/**
	 * @brief Write hybrid header: eskLen(4 BE) || esk || iv.
	 * @param esk Encrypted session key.
	 * @param iv IV.
	 * @param out Destination.
	 * @return true on success.
	 */
	bool WriteEnvelopeHeader(const Buffer::DataType& esk,
							const CryptoPP::SecByteBlock& iv,
							Buffer::DataType& out) noexcept;

	/**
	 * @brief Parse eskLen (4 bytes, big-endian).
	 * @param lenBytes Length field.
	 * @return Length, or 0 if size is not 4.
	 */
	std::uint32_t ParseEskLength(const Buffer::DataType& lenBytes) noexcept;

	/**
	 * @brief One-shot native PK transform.
	 * @param data Input.
	 * @param output Destination.
	 * @param box Engine.
	 * @return true on success.
	 */
	bool NativeProcessSpan(std::span<const std::byte> data,
						Buffer::WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief Streaming native PK. Each chunk is independent.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param box Engine.
	 * @return Consumer with the result.
	 */
	Buffer::Consumer NativeProcessStream(Buffer::Consumer consumer,
										ReadMode mode,
										std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief One-shot hybrid encrypt. box wraps the session key.
	 * @param data Input.
	 * @param output Destination.
	 * @param box Public-key box.
	 * @return true on success.
	 */
	bool HybridEncryptSpan(std::span<const std::byte> data,
						Buffer::WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief Streaming hybrid encrypt.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param box Public-key box.
	 * @return Consumer with the envelope.
	 */
	Buffer::Consumer HybridEncryptStream(Buffer::Consumer consumer,
										ReadMode mode,
										std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief One-shot hybrid decrypt. box unwraps the session key.
	 * @param data Input.
	 * @param output Destination.
	 * @param box Private-key box.
	 * @return true on success.
	 */
	bool HybridDecryptSpan(std::span<const std::byte> data,
						Buffer::WriteOnly& output,
						std::unique_ptr<PkBox> box) noexcept;

	/**
	 * @brief Streaming hybrid decrypt.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param box Private-key box.
	 * @return Consumer with the plaintext.
	 */
	Buffer::Consumer HybridDecryptStream(Buffer::Consumer consumer,
										ReadMode mode,
										std::unique_ptr<PkBox> box) noexcept;
}
