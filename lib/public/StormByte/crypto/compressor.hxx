#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/expected.hxx>

#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Compressor
	 * @brief A class for managing data compression and decompression.
	 *
	 * This class provides methods for compressing and decompressing data using various compression algorithms.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Compressor final {
		public:
			/**
			 * @brief Initializes a Compressor instance with the specified compression algorithm.
			 * @param algorithm The compression algorithm to use.
			 */
			explicit Compressor(const Algorithm::Compress& algorithm) noexcept;

			/**
			 * @brief Copy constructor for the Compressor class.
			 * @param compressor The Compressor instance to copy.
			 */
			Compressor(const Compressor& compressor) 					= default;

			/**
			 * @brief Move constructor for the Compressor class.
			 * @param compressor The Compressor instance to move.
			 */
			Compressor(Compressor&& compressor) noexcept 				= default;

			/**
			 * @brief Destructor for the Compressor class.
			 */
			~Compressor() noexcept 										= default;

			/**
			 * @brief Copy assignment operator for the Compressor class.
			 * @param compressor The Compressor instance to copy.
			 * @return A reference to the updated Compressor instance.
			 */
			Compressor& operator=(const Compressor& compressor) 		= default;

			/**
			 * @brief Move assignment operator for the Compressor class.
			 * @param compressor The Compressor instance to move.
			 * @return A reference to the updated Compressor instance.
			 */
			Compressor& operator=(Compressor&& compressor) noexcept 	= default;

			/**
			 * @brief Compresses a string input using the specified compression algorithm.
			 * @param input The string to compress.
			 * @return An Expected containing the compressed string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception> 							Compress(const std::string& input) const noexcept;

			/**
			 * @brief Compresses a buffer using the specified compression algorithm.
			 * @param buffer The buffer to compress.
			 * @return An Expected containing the compressed buffer or an error.
			 */
			[[nodiscard]]
			Expected<Buffer::FIFO, Exception> 						Compress(const Buffer::FIFO& buffer) const noexcept;

			/**
			 * @brief Compresses data asynchronously using a Consumer/Producer model.
			 * @param consumer The Consumer buffer containing the input data.
			 * @return A Consumer buffer containing the compressed data.
			 */
			[[nodiscard]]
			Buffer::Consumer 											Compress(const Buffer::Consumer consumer) const noexcept;

			/**
			 * @brief Decompresses a string input using the specified compression algorithm.
			 * @param input The string to decompress.
			 * @return An Expected containing the decompressed string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception> 							Decompress(const std::string& input) const noexcept;

			/**
			 * @brief Decompresses a buffer using the specified compression algorithm.
			 * @param buffer The buffer to decompress.
			 * @return An Expected containing the decompressed buffer or an error.
			 */
			[[nodiscard]]
			Expected<Buffer::FIFO, Exception> 						Decompress(const Buffer::FIFO& buffer) const noexcept;

			/**
			 * @brief Decompresses data asynchronously using a Consumer/Producer model.
			 * @param consumer The Consumer buffer containing the compressed data.
			 * @return A Consumer buffer containing the decompressed data.
			 */
			[[nodiscard]]
			Buffer::Consumer 											Decompress(const Buffer::Consumer consumer) const noexcept;

		private:
			const Algorithm::Compress m_algorithm; ///< The compression algorithm to use.
	};
}