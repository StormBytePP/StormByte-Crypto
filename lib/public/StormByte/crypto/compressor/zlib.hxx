#pragma once

#include <StormByte/crypto/compressor/generic.hxx>

/**
 * @namespace Compressor
 * @brief The namespace containing all the compressor-related classes.
 */
namespace StormByte::Crypto::Compressor {
	/**
	 * @class Zlib
	 * @brief A class representing the Zlib compression algorithm.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Zlib final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param level The compression level.
			 */
			Zlib(unsigned short level = 5);

			/**
			 * @brief Copy constructor
			 * @param other The other Zlib compressor to copy from.
			 */
			Zlib(const Zlib& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other Zlib compressor to move from.
			 */
			Zlib(Zlib&& other) noexcept							= default;

			/**
			 * @brief Virtual destructor
			 */
			~Zlib() noexcept 									= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Zlib compressor to copy from.
			 * @return Reference to this Zlib compressor.
			 */
			Zlib& operator=(const Zlib& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Zlib compressor to move from.
			 * @return Reference to this Zlib compressor.
			 */
			Zlib& operator=(Zlib&& other) noexcept				= default;

			/**
			 * @brief Clone the Zlib compressor.
			 * @return A unique pointer to the cloned Zlib compressor.
			 */
			PointerType 										Clone() const override {
				return std::make_unique<Zlib>(*this);
			}

			/**
			 * @brief Move the Zlib compressor.
			 * @return A unique pointer to the moved Zlib compressor.
			 */
			PointerType 										Move() noexcept override {
				return std::make_unique<Zlib>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the compression logic.
			 * @param input The input buffer to compress.
			 * @param output The output buffer to write the compressed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if compression was successful, false otherwise.
			 */
			bool 												DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the compression logic for Consumer buffers.
			 * @param consumer The Consumer buffer to compress.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the compressed data.
			 */
			Buffer::Consumer 									DoCompress(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Implementation of the decompression logic.
			 * @param input The input buffer to decompress.
			 * @param output The output buffer to write the decompressed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if decompression was successful, false otherwise.
			 */
			bool 												DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the decompression logic for Consumer buffers.
			 * @param consumer The Consumer buffer to decompress.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decompressed data.
			 */
			Buffer::Consumer 									DoDecompress(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}