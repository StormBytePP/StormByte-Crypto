#pragma once

#include <StormByte/crypto/crypter.hxx>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Symmetric
	 * @brief A class for managing symmetric encryption and decryption.
	 *
	 * This class provides methods for encrypting and decrypting data using symmetric encryption algorithms.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Symmetric final: public Crypter {
		public:
			/**
			 * @brief Constructs a Symmetric instance with a randomly generated password.
			 * 
			 * This constructor initializes the `Symmetric` instance with the specified symmetric encryption algorithm
			 * and a randomly generated password of the specified size.
			 * 
			 * @param algorithm The symmetric encryption algorithm to use.
			 * @param password_size The size of the randomly generated password (default is 16 bytes).
			 */
			Symmetric(const Algorithm::Symmetric& algorithm, const size_t& password_size = 16) noexcept;

			/**
			 * @brief Constructs a Symmetric instance with a user-provided password.
			 * 
			 * This constructor initializes the `Symmetric` instance with the specified symmetric encryption algorithm
			 * and a user-provided password.
			 * 
			 * @param algorithm The symmetric encryption algorithm to use.
			 * @param password The password to use for encryption and decryption.
			 */
			explicit Symmetric(const Algorithm::Symmetric& algorithm, const std::string& password) noexcept;

			// Default constructors, destructors, and assignment operators
			/**
			 * @brief Copy constructor for the Symmetric class.
			 * 
			 * Creates a copy of the given `Symmetric` instance.
			 * 
			 * @param crypter The `Symmetric` instance to copy.
			 */
			Symmetric(const Symmetric& crypter) 					= default;

			/**
			 * @brief Move constructor for the Symmetric class.
			 * 
			 * Moves the given `Symmetric` instance into the current instance.
			 * 
			 * @param crypter The `Symmetric` instance to move.
			 */
			Symmetric(Symmetric&& crypter) noexcept 				= default;

			/**
			 * @brief Destructor for the Symmetric class.
			 * 
			 * Cleans up the `Symmetric` instance.
			 */
			~Symmetric() noexcept override 							= default;

			/**
			 * @brief Copy assignment operator for the Symmetric class.
			 * 
			 * Assigns the values from the given `Symmetric` instance to the current instance.
			 * 
			 * @param crypter The `Symmetric` instance to copy.
			 * @return A reference to the updated `Symmetric` instance.
			 */
			Symmetric& operator=(const Symmetric& crypter) 			= default;

			/**
			 * @brief Move assignment operator for the Symmetric class.
			 * 
			 * Moves the values from the given `Symmetric` instance to the current instance.
			 * 
			 * @param crypter The `Symmetric` instance to move.
			 * @return A reference to the updated `Symmetric` instance.
			 */
			Symmetric& operator=(Symmetric&& crypter) noexcept 		= default;

			/**
			 * @brief Encrypts a string input.
			 * 
			 * This method encrypts the given string input using the symmetric encryption algorithm.
			 * 
			 * @param input The string to encrypt.
			 * @return An Expected containing the encrypted string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception> 						Encrypt(const std::string& input) const noexcept override;

			/**
			 * @brief Encrypts a buffer.
			 * 
			 * This method encrypts the given buffer using the symmetric encryption algorithm.
			 * 
			 * @param buffer The buffer to encrypt.
			 * @return An Expected containing the encrypted buffer or an error.
			 */
			[[nodiscard]]
			Expected<Buffer::FIFO, Exception> 					Encrypt(const Buffer::FIFO& buffer) const noexcept override;

			/**
			 * @brief Encrypts data asynchronously using a Consumer/Producer model.
			 * 
			 * This method encrypts the data provided by the Consumer buffer using the symmetric encryption algorithm.
			 * 
			 * @param consumer The Consumer buffer containing the input data.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			[[nodiscard]]
			Buffer::Consumer 										Encrypt(const Buffer::Consumer consumer) const noexcept override;

			/**
			 * @brief Decrypts a string input.
			 * 
			 * This method decrypts the given string input using the symmetric encryption algorithm.
			 * 
			 * @param input The string to decrypt.
			 * @return An Expected containing the decrypted string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception> 						Decrypt(const std::string& input) const noexcept override;

			/**
			 * @brief Decrypts a buffer.
			 * 
			 * This method decrypts the given buffer using the symmetric encryption algorithm.
			 * 
			 * @param buffer The buffer to decrypt.
			 * @return An Expected containing the decrypted buffer or an error.
			 */
			[[nodiscard]]
			Expected<Buffer::FIFO, Exception> 					Decrypt(const Buffer::FIFO& buffer) const noexcept override;

			/**
			 * @brief Decrypts data asynchronously using a Consumer/Producer model.
			 * 
			 * This method decrypts the data provided by the Consumer buffer using the symmetric encryption algorithm.
			 * 
			 * @param consumer The Consumer buffer containing the encrypted data.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			[[nodiscard]]
			Buffer::Consumer 										Decrypt(const Buffer::Consumer consumer) const noexcept override;

			/**
			 * @brief Returns the password used for encryption and decryption.
			 * 
			 * This method returns the password used by the `Symmetric` instance for encryption and decryption.
			 * 
			 * @return The password as a string.
			 */
			const std::string& 										Password() const noexcept;

			/**
			 * @brief Sets the password for encryption and decryption.
			 * 
			 * This method sets a new password for the `Symmetric` instance to use for encryption and decryption.
			 * 
			 * @param password The new password to use.
			 */
			void 													Password(const std::string& password) noexcept;

			/**
			 * @brief Sets the password for encryption and decryption (move version).
			 * 
			 * This method sets a new password for the `Symmetric` instance to use for encryption and decryption.
			 * The password is moved into the instance to avoid unnecessary copying.
			 * 
			 * @param password The new password to use (rvalue reference).
			 */
			void 													Password(std::string&& password) noexcept;

		private:
			Algorithm::Symmetric m_algorithm;						///< The symmetric encryption algorithm to use.
			std::string m_password;									///< The password used for encryption/decryption.
	};
}