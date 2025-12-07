#pragma once

#include <StormByte/crypto/implementation/hash/typedefs.h>

/**
 * @namespace Blake2b
 * @brief Namespace for Blake2b hashing utilities.
 */
namespace StormByte::Crypto::Implementation::Hash::Blake2b {
	/**
	 * @brief Hashes the input data using Blake2b.
	 * @param input The input string to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString 		Hash(const std::string& input) noexcept;

	/**
	 * @brief Hashes the input data using Blake2b.
	 * @param buffer The input buffer to hash.
	 * @return Expected<std::string, CryptoException> containing the hash or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedHashString 		Hash(const Buffer::FIFO& buffer) noexcept;

	/**
	 * @brief Hashes data asynchronously using the Buffer::Consumer/Buffer::Producer model.
	 * 
	 * @param Buffer::Consumer The Buffer::Consumer buffer containing the input data.
	 * @return A Buffer::Consumer buffer containing the hash result.
	 */
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer 	Hash(Buffer::Consumer consumer) noexcept;
}