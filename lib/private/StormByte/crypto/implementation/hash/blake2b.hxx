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
    STORMBYTE_CRYPTO_PRIVATE ExpectedHashFutureString 		Hash(const std::string& input) noexcept;

    /**
     * @brief Hashes the input data using Blake2b.
     * @param buffer The input buffer to hash.
     * @return Expected<std::string, CryptoException> containing the hash or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedHashFutureString 		Hash(const Buffers::Simple& buffer) noexcept;

    /**
     * @brief Hashes data asynchronously using the Consumer/Producer model.
     * 
     * @param consumer The Consumer buffer containing the input data.
     * @return A Consumer buffer containing the hash result.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer 	Hash(const Buffers::Consumer consumer) noexcept;
}