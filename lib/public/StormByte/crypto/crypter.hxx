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
	 * @class Crypter
	 * @brief An abstract base class for encryption and decryption operations.
	 *
	 * This class defines the interface for encrypting and decrypting data using various cryptographic algorithms.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Crypter {
		public:
			/**
			 * @brief Default constructor for the Crypter class.
			 */
			Crypter() noexcept									= default;

			/**
			 * @brief Copy constructor for the Crypter class.
			 * @param crypter The Crypter instance to copy.
			 */
			Crypter(const Crypter& crypter) 					= default;

			/**
			 * @brief Move constructor for the Crypter class.
			 * @param crypter The Crypter instance to move.
			 */
			Crypter(Crypter&& crypter) noexcept 				= default;

			/**
			 * @brief Virtual destructor for the Crypter class.
			 */
			virtual ~Crypter() noexcept 						= default;

			/**
			 * @brief Copy assignment operator for the Crypter class.
			 * @param crypter The Crypter instance to copy.
			 * @return A reference to the updated Crypter instance.
			 */
			Crypter& operator=(const Crypter& crypter) 			= default;

			/**
			 * @brief Move assignment operator for the Crypter class.
			 * @param crypter The Crypter instance to move.
			 * @return A reference to the updated Crypter instance.
			 */
			Crypter& operator=(Crypter&& crypter) noexcept 		= default;

			/**
			 * @brief Encrypts a string input.
			 * @param input The string to encrypt.
			 * @return An Expected containing the encrypted string or an error.
			 */
			[[nodiscard]]
			virtual Expected<std::string, Exception>			Encrypt(const std::string& input) const noexcept = 0;

			/**
			 * @brief Encrypts a buffer.
			 * @param buffer The buffer to encrypt.
			 * @return An Expected containing the encrypted buffer or an error.
			 */
			[[nodiscard]]
			virtual Expected<Buffer::Simple, Exception>		Encrypt(const Buffer::Simple& buffer) const noexcept = 0;

			/**
			 * @brief Encrypts data asynchronously using a Consumer/Producer model.
			 * @param consumer The Consumer buffer containing the input data.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			[[nodiscard]]
			virtual Buffer::Consumer 							Encrypt(const Buffer::Consumer consumer) const noexcept = 0;

			/**
			 * @brief Decrypts a string input.
			 * @param input The string to decrypt.
			 * @return An Expected containing the decrypted string or an error.
			 */
			[[nodiscard]]
			virtual Expected<std::string, Exception>			Decrypt(const std::string& input) const noexcept = 0;

			/**
			 * @brief Decrypts a buffer.
			 * @param buffer The buffer to decrypt.
			 * @return An Expected containing the decrypted buffer or an error.
			 */
			[[nodiscard]]
			virtual Expected<Buffer::Simple, Exception>		Decrypt(const Buffer::Simple& buffer) const noexcept = 0;

			/**
			 * @brief Decrypts data asynchronously using a Consumer/Producer model.
			 * @param consumer The Consumer buffer containing the encrypted data.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			[[nodiscard]]
			virtual Buffer::Consumer 							Decrypt(const Buffer::Consumer consumer) const noexcept = 0;
	};
}