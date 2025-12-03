#pragma once

#include <StormByte/crypto/implementation/compressor/typedefs.hxx>

/**
 * @namespace Zlib
 * @brief The namespace containing Zlib (Deflate) compression and decompression functions.
 */
namespace StormByte::Crypto::Implementation::Compressor::Zlib {
	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Compress(const std::string& input) noexcept;
	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Compress(const StormByte::Buffer::FIFO& input) noexcept;
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Compress(const Buffer::Consumer consumer) noexcept;

	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Decompress(const std::string& input) noexcept;
	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Decompress(const StormByte::Buffer::FIFO& input) noexcept;
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Decompress(const Buffer::Consumer consumer) noexcept;
}
