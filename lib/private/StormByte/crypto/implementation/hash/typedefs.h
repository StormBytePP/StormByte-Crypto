#pragma once

#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/implementation/typedefs.hxx>

/**
 * @namespace Hash
 * @brief The namespace containing hashing functions
 */
namespace StormByte::Crypto::Implementation::Hash {
	using ExpectedHashBuffer = StormByte::Expected<Buffer::FIFO, Exception>;			///< The expected hash buffer type.
	using ExpectedHashString = StormByte::Expected<std::string, Exception>;					///< The expected hash string type.
}