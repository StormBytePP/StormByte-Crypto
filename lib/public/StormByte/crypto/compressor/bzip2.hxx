#pragma once

#include <StormByte/crypto/compressor/generic.hxx>

/**
 * @namespace Compressor
 * @brief The namespace containing all the compressor-related classes.
 */
namespace StormByte::Crypto::Compressor {
	/**
	 * @class Bzip2
	 * @brief A class representing the Bzip2 compression algorithm.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Bzip2 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param level The compression level.
			 */
			Bzip2(unsigned short level = 5);

			/**
			 * @brief Copy constructor
			 * @param other The other Bzip2 compressor to copy from.
			 */
			Bzip2(const Bzip2& other)							= default;

			/**
			 * @brief Move constructor
			 * @param other The other Bzip2 compressor to move from.
			 */
			Bzip2(Bzip2&& other) noexcept						= default;

			/**
			 * @brief Virtual destructor
			 */
			~Bzip2() noexcept 									= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Bzip2 compressor to copy from.
			 * @return Reference to this Bzip2 compressor.
			 */
			Bzip2& operator=(const Bzip2& other)				= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Bzip2 compressor to move from.
			 * @return Reference to this Bzip2 compressor.
			 */
			Bzip2& operator=(Bzip2&& other) noexcept			= default;

			/**
			 * @brief Clone the Bzip2 compressor.
			 * @return A unique pointer to the cloned Bzip2 compressor.
			 */
			inline PointerType 									Clone() const override {
				return std::make_unique<Bzip2>(*this);
			}

			/**
			 * @brief Move the Bzip2 compressor.
			 * @return A unique pointer to the moved Bzip2 compressor.
			 */
			inline PointerType 									Move() noexcept override {
				return std::make_unique<Bzip2>(std::move(*this));
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