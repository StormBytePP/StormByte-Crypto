#pragma once

#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/implementation/typedefs.hxx>

/**
 * @namespace Compressor
 * @brief The namespace containing Compression functions
 */
namespace StormByte::Crypto::Implementation::Compressor {
	using ExpectedCompressorBuffer = StormByte::Expected<Buffer::FIFO, Exception>;				///< The expected compressor buffer type.
	using ExpectedCompressorString = StormByte::Expected<std::string, Exception>;				///< The expected compressor string type.
}