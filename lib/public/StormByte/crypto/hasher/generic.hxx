#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/clonable.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

/**
 * @namespace Hasher
 * @brief The namespace containing all the hasher-related classes.
 */
namespace StormByte::Crypto::Hasher {
	/**
	 * @enum Type
	 * @brief The types of hashers available.
	 */
	enum class Type {
		Blake2b,												///< BLAKE2b Hash Function
		Blake2s,												///< BLAKE2s Hash Function
		SHA3_256,												///< SHA3-256 Hash Function
		SHA3_512,												///< SHA3-512 Hash Function
		SHA256,												///< SHA-256 Hash Function
		SHA512,												///< SHA-512 Hash Function
	};

	/**
	 * @class Generic
	 * @brief A generic hasher class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Generic hasher to copy from.
			 */
			Generic(const Generic& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other Generic hasher to move from.
			 */
			Generic(Generic&& other) noexcept					= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Generic() noexcept 						= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Generic hasher to copy from.
			 * @return Reference to this Generic hasher.
			 */
			Generic& operator=(const Generic& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Generic hasher to move from.
			 * @return Reference to this Generic hasher.
			 */
			Generic& operator=(Generic&& other) noexcept		= default;

			/**
			 * @brief Hash data from input buffer to output buffer.
			 * @param input The input buffer to hash.
			 * @param output The output buffer to write the hashed data to.
			 * @return true if hashing was successful, false otherwise.
			 */
			inline bool 										Hash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoHash(input, output);
			}

			/**
			 * @brief Hash data from input buffer to output buffer.
			 * @param input The input buffer to hash.
			 * @param output The output buffer to write the hashed data to.
			 * @return true if hashing was successful, false otherwise.
			 */
			inline bool 										Hash(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoHash(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Hash data from input buffer to output buffer, moving the input data.
			 * @param input The input buffer to hash.
			 * @param output The output buffer to write the hashed data to.
			 * @return true if hashing was successful, false otherwise.
			 */
			inline bool 										Hash(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoHash(input, output, ReadMode::Move);
			}

			/**
			 * @brief Hash data from a Consumer buffer.
			 * @param consumer The Consumer buffer to hash.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the hashed data.
			 */
			inline Buffer::Consumer 							Hash(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoHash(consumer, mode);
			}

			/**
			 * @brief Gets the type of hasher.
			 * @return The type of hasher.
			 */
			inline enum Type 									Type() const noexcept {
				return m_type;
			}

		protected:
			enum Type m_type;									///< The type of hasher

			/**
			 * @brief Constructor
			 * @param type The type of hasher.
			 */
			inline 												Generic(enum Type type):
			m_type(type) {}

		private:
			/**
			 * @brief Implementation of the hashing logic.
			 * @param input The input buffer to hash.
			 * @param output The output buffer to write the hashed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if hashing was successful, false otherwise.
			 */
			bool 												DoHash(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Implementation of the hashing logic.
			 * @param input The input buffer to hash.
			 * @param output The output buffer to write the hashed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if hashing was successful, false otherwise.
			 */
			virtual bool 										DoHash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Implementation of the hashing logic for Consumer buffers.
			 * @param consumer The Consumer buffer to hash.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the hashed data.
			 */
			virtual Buffer::Consumer 							DoHash(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;
	};

	/**
	 * @brief Factory method to create a hasher.
	 * @param type The type of hasher to create.
	 * @return A pointer to the created hasher.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 				Create(Type type) noexcept;
}