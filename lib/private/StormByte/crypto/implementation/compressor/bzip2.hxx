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
     * @return An `ExpectedCompressorFutureBuffer` containing the compressed data as a future, or an error if compression fails.
     * 
     * @note The compression is performed asynchronously, and the result is returned as a future.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorFutureBuffer Compress(const std::string& input) noexcept;

    /**
     * @brief Compresses the input buffer using the BZip2 compression algorithm.
     * 
     * @param input The input buffer to compress.
     * @return An `ExpectedCompressorFutureBuffer` containing the compressed data as a future, or an error if compression fails.
     * 
     * @note The compression is performed asynchronously, and the result is returned as a future.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorFutureBuffer Compress(const StormByte::Buffers::Simple& input) noexcept;

    /**
     * @brief Compresses the input buffer using the BZip2 compression algorithm.
     * 
     * @param input The input buffer to compress.
     * @return An `ExpectedCompressorFutureBuffer` containing the compressed data as a future, or an error if compression fails.
     * 
     * @note The compression is performed asynchronously, and the result is returned as a future.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer Compress(const Buffers::Consumer consumer) noexcept;

    /**
     * @brief Decompresses the input string using the BZip2 decompression algorithm.
     * 
     * @param input The compressed input string to decompress.
     * @return An `ExpectedCompressorFutureBuffer` containing the decompressed data as a future, or an error if decompression fails.
     * 
     * @note The decompression is performed asynchronously, and the result is returned as a future.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorFutureBuffer Decompress(const std::string& input) noexcept;

    /**
     * @brief Decompresses the input buffer using the BZip2 decompression algorithm.
     * 
     * @param input The compressed input buffer to decompress.
     * @return An `ExpectedCompressorFutureBuffer` containing the decompressed data as a future, or an error if decompression fails.
     * 
     * @note The decompression is performed asynchronously, and the result is returned as a future.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCompressorFutureBuffer Decompress(const StormByte::Buffers::Simple& input) noexcept;

    /**
     * @brief Decompresses the input buffer using the BZip2 decompression algorithm.
     * 
     * @param input The compressed input buffer to decompress.
     * @return A `StormByte::Buffers::Consumer` containing the decompressed data as a consumer, or an error if decompression fails.
     * 
     * @note The decompression is performed asynchronously, and the result is returned as a consumer.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer Decompress(const Buffers::Consumer& consumer) noexcept;
}