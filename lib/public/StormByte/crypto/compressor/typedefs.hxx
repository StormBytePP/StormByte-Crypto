#pragma once

#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/typedefs.hxx>

/**
 * @namespace Compressor
 * @brief The namespace containing Compression functions
 */
namespace StormByte::Crypto::Compressor {
	using ExpectedCompressorFutureBuffer = StormByte::Expected<FutureBuffer, Exception>;			///< The expected crypto buffer type.
	using ExpectedCompressorFutureString = StormByte::Expected<std::string, Exception>;				///< The expected crypto string type.
}