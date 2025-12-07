#pragma once

#include <StormByte/crypto/implementation/hash/typedefs.h>

/**
 * @namespace SHA3_256
 * @brief Namespace for SHA3-256 hashing utilities.
 */
namespace StormByte::Crypto::Implementation::Hash::SHA3_256 {
	/**
	 * @brief Hashes the input data using SHA3-256.
	 * @param input The input string to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString Hash(const std::string& input) noexcept;

	/**
	 * @brief Hashes the input data using SHA3-256.
	 * @param buffer The input buffer to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString Hash(const Buffer::FIFO& buffer) noexcept;

	/**
	 * @brief Hashes data asynchronously using the Buffer::Consumer/Buffer::Producer model.
	 * 
	 * @param Buffer::Consumer The Buffer::Consumer buffer containing the input data.
	 * @return A Buffer::Consumer buffer containing the hash result.
	 */
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Hash(Buffer::Consumer consumer) noexcept;
}

/**
 * @namespace SHA3_512
 * @brief Namespace for SHA3-512 hashing utilities.
 */
namespace StormByte::Crypto::Implementation::Hash::SHA3_512 {
	/**
	 * @brief Hashes the input data using SHA3-512.
	 * @param input The input string to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString Hash(const std::string& input) noexcept;

	/**
	 * @brief Hashes the input data using SHA3-512.
	 * @param buffer The input buffer to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString Hash(const Buffer::FIFO& buffer) noexcept;

	/**
	 * @brief Hashes data asynchronously using the Buffer::Consumer/Buffer::Producer model.
	 * 
	 * @param Buffer::Consumer The Buffer::Consumer buffer containing the input data.
	 * @return A Buffer::Consumer buffer containing the hash result.
	 */
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Hash(Buffer::Consumer consumer) noexcept;
}
