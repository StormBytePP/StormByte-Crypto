#pragma once

#include <StormByte/crypto/implementation/compressor/typedefs.hxx>

/**
 * @namespace BZip2
 * @brief The namespace containing BZip2 compression functions.
 */
namespace StormByte::Crypto::Implementation::Compressor::BZip2 {
	/**
	 * @brief Compresses the input string using the BZip2 compression algorithm.
	 * 
	 * @param input The input string to compress.
	 * @return An `ExpectedCompressorBuffer` containing the compressed data, or an error if compression fails.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Compress(const std::string& input) noexcept;

	/**
	 * @brief Compresses the input buffer using the BZip2 compression algorithm.
	 * 
	 * @param input The input buffer to compress.
	 * @return An `ExpectedCompressorBuffer` containing the compressed data, or an error if compression fails.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Compress(const StormByte::Buffer::FIFO& input) noexcept;

	/**
	 * @brief Compresses the input buffer using the BZip2 compression algorithm (streaming).
	 * 
	 * @param consumer The input buffer consumer to compress from.
	 * @return A `StormByte::Buffer::Consumer` for reading compressed data.
	 * 
	 * @note The compression is performed asynchronously in a separate thread.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Compress(Buffer::Consumer consumer) noexcept;

	/**
	 * @brief Decompresses the input string using the BZip2 decompression algorithm.
	 * 
	 * @param input The compressed input string to decompress.
	 * @return An `ExpectedCompressorBuffer` containing the decompressed data, or an error if decompression fails.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Decompress(const std::string& input) noexcept;

	/**
	 * @brief Decompresses the input buffer using the BZip2 decompression algorithm.
	 * 
	 * @param input The compressed input buffer to decompress.
	 * @return An `ExpectedCompressorBuffer` containing the decompressed data, or an error if decompression fails.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorBuffer Decompress(const StormByte::Buffer::FIFO& input) noexcept;

	/**
	 * @brief Decompresses the input buffer using the BZip2 decompression algorithm (streaming).
	 * 
	 * @param consumer The compressed input buffer consumer to decompress from.
	 * @return A `StormByte::Buffer::Consumer` for reading decompressed data.
	 * 
	 * @note The decompression is performed asynchronously in a separate thread.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Decompress(Buffer::Consumer consumer) noexcept;
}