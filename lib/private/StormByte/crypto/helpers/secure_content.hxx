#pragma once

#include <StormByte/crypto/visibility.h>

#include <cstddef>
#include <secblock.h>

/**
 * @namespace Helpers
 * @brief Private helpers for the Crypto module (headers are not installed).
 */
namespace StormByte::Crypto::Helpers {

	/**
	 * @class SecureContent
	 * @brief Opaque secure byte buffer backed by Crypto++ SecByteBlock.
	 *
	 * Stores an exact number of bytes (no forced null terminator).
	 * Must only be used from library implementation units.
	 */
	class STORMBYTE_CRYPTO_PRIVATE SecureContent {
		public:
			/**
			 * @brief Construct from raw bytes.
			 * @param data Pointer to source bytes (may be nullptr if size is 0).
			 * @param size Exact number of bytes to store.
			 */
			SecureContent(const void* data, std::size_t size) noexcept;

			SecureContent(const SecureContent&) = delete;
			SecureContent& operator=(const SecureContent&) = delete;

			/**
			 * @brief Securely zero the buffer.
			 */
			void Wipe() noexcept;

			/**
			 * @brief Byte length of the stored content.
			 * @return Size in bytes.
			 */
			std::size_t Size() const noexcept;

			/**
			 * @brief Pointer to the stored bytes (valid while this object lives).
			 * @return Pointer to the data, or valid empty pointer if size is 0.
			 */
			const unsigned char* Data() const noexcept;

			/**
			 * @brief Constant-time equality comparison.
			 * @param other The other buffer to compare with.
			 * @return true if lengths and contents match, false otherwise.
			 */
			bool Equal(const SecureContent& other) const noexcept;

		private:
			CryptoPP::SecByteBlock m_block;	///< Backing storage with cleanup allocator
	};
}
