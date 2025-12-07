#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/clonable.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

/**
 * @namespace Compressor
 * @brief The namespace containing all the compressor-related classes.
 */
namespace StormByte::Crypto::Compressor {
	/**
	 * @enum Type
	 * @brief The types of compressors available.
	 */
	enum class Type {
		Bzip2,													///< Bzip2 compressor
		Zlib													///< Zlib compressor
	};

	/**
	 * @class Generic
	 * @brief A generic compressor class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Generic compressor to copy from.
			 */
			Generic(const Generic& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other Generic compressor to move from.
			 */
			Generic(Generic&& other) noexcept					= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Generic() noexcept 						= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Generic compressor to copy from.
			 * @return Reference to this Generic compressor.
			 */
			Generic& operator=(const Generic& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Generic compressor to move from.
			 * @return Reference to this Generic compressor.
			 */
			Generic& operator=(Generic&& other) noexcept		= default;

			/**
			 * @brief Compress data from input buffer to output buffer.
			 * @param input The input buffer to compress.
			 * @param output The output buffer to write the compressed data to.
			 * @return true if compression was successful, false otherwise.
			 */
			inline bool 										Compress(const std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoCompress(input, output);
			}

			/**
			 * @brief Compress data from input buffer to output buffer.
			 * @param input The input buffer to compress.
			 * @param output The output buffer to write the compressed data to.
			 * @return true if compression was successful, false otherwise.
			 */
			inline bool 										Compress(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoCompress(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Compress data from input buffer to output buffer, moving the input data.
			 * @param input The input buffer to compress.
			 * @param output The output buffer to write the compressed data to.
			 * @return true if compression was successful, false otherwise.
			 */
			inline bool 										Compress(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoCompress(input, output, ReadMode::Move);
			}

			/**
			 * @brief Compress data from a Consumer buffer.
			 * @param consumer The Consumer buffer to compress.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the compressed data.
			 */
			inline Buffer::Consumer 							Compress(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoCompress(consumer, mode);
			}

			/**
			 * @brief Decompress data from input buffer to output buffer.
			 * @param input The input buffer to decompress.
			 * @param output The output buffer to write the decompressed data to.
			 * @return true if decompression was successful, false otherwise.
			 */
			inline bool 										Decompress(const std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoDecompress(input, output);
			}

			/**
			 * @brief Decompress data from input buffer to output buffer.
			 * @param input The input buffer to decompress.
			 * @param output The output buffer to write the decompressed data to.
			 * @return true if decompression was successful, false otherwise.
			 */
			inline bool 										Decompress(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecompress(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Decompress data from input buffer to output buffer, moving the input data.
			 * @param input The input buffer to decompress.
			 * @param output The output buffer to write the decompressed data to.
			 * @return true if decompression was successful, false otherwise.
			 */
			inline bool 										Decompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecompress(input, output, ReadMode::Move);
			}

			/**
			 * @brief Decompress data from a Consumer buffer.
			 * @param consumer The Consumer buffer to decompress.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the compressed data.
			 */
			inline Buffer::Consumer 							Decompress(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoDecompress(consumer, mode);
			}

			/**
			 * @brief Gets the compression level.
			 * @return The compression level.
			 */
			unsigned short 										Level() const noexcept {
				return m_level;
			}

			/**
			 * @brief Gets the type of compressor.
			 * @return The type of compressor.
			 */
			inline enum Type 									Type() const noexcept {
				return m_type;
			}

		protected:
			enum Type m_type;									///< The type of compressor
			unsigned short m_level = 0;							///< The compression level

			/**
			 * @brief Constructor
			 * @param type The type of compressor.
			 */
			inline 												Generic(enum Type type, unsigned short level = 5):
			m_type(type), m_level(level) {}

		private:
			/**
			 * @brief Implementation of the compression logic.
			 * @param input The input buffer to compress.
			 * @param output The output buffer to write the compressed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if compression was successful, false otherwise.
			 */
			virtual bool 										DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Implementation of the compression logic.
			 * @param input The input buffer to compress.
			 * @param output The output buffer to write the compressed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if compression was successful, false otherwise.
			 */
			bool 												DoCompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Implementation of the compression logic for Consumer buffers.
			 * @param consumer The Consumer buffer to compress.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the compressed data.
			 */
			virtual Buffer::Consumer 							DoCompress(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

			/**
			 * @brief Implementation of the decompression logic.
			 * @param input The input buffer to decompress.
			 * @param output The output buffer to write the decompressed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if decompression was successful, false otherwise.
			 */
			virtual bool 										DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Implementation of the decompression logic.
			 * @param input The input buffer to decompress.
			 * @param output The output buffer to write the decompressed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if decompression was successful, false otherwise.
			 */
			bool 												DoDecompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Implementation of the decompression logic for Consumer buffers.
			 * @param consumer The Consumer buffer to decompress.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decompressed data.
			 */
			virtual Buffer::Consumer 							DoDecompress(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;
	};

	/**
	 * @brief Factory method to create a Generic compressor.
	 * @param type The type of compressor to create.
	 * @param level The compression level.
	 * @return A pointer to the created Generic compressor.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 				Create(Type type, unsigned short level) noexcept;
}