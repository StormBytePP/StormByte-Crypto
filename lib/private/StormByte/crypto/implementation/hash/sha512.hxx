#pragma once

#include <StormByte/crypto/implementation/hash/typedefs.h>

/**
 * @namespace SHA512
 * @brief Namespace for SHA-512 hashing utilities.
 */
namespace StormByte::Crypto::Implementation::Hash::SHA512 {
	/**
	 * @brief Hashes the input data using SHA-512.
	 * @param input The input string to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString Hash(const std::string& input) noexcept;

	/**
	 * @brief Hashes the input data using SHA-512.
	 * @param buffer The input buffer to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString Hash(const Buffer::FIFO& buffer) noexcept;

	/**
	 * @brief Hashes data asynchronously using the Consumer/Producer model.
	 * 
	 * @param consumer The Consumer buffer containing the input data.
	 * @return A Consumer buffer containing the hash result.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Hash(Buffer::Consumer consumer) noexcept;
}