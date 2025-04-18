#pragma once

#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/implementation/typedefs.hxx>

/**
 * @namespace Hash
 * @brief The namespace containing hashing functions
 */
namespace StormByte::Crypto::Implementation::Hash {
	using ExpectedHashFutureBuffer = StormByte::Expected<FutureBuffer, Exception>;			///< The expected crypto buffer type.
	using ExpectedHashFutureString = StormByte::Expected<std::string, Exception>;			///< The expected crypto string type.
}