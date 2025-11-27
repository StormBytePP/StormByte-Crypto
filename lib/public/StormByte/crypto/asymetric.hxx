#pragma once

#include <StormByte/crypto/crypter.hxx>
#include <StormByte/crypto/keypair.hxx>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Asymmetric
	 * @brief A class for managing asymmetric encryption and decryption.
	 *
	 * This class provides methods for encrypting and decrypting data using asymmetric encryption algorithms.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Asymmetric final : public Crypter {
		public:
			/**
			 * @brief Constructs an Asymmetric instance with a specified algorithm and key pair.
			 * @param algorithm The asymmetric encryption algorithm to use.
			 * @param key_pair The key pair to use for encryption and decryption.
			 */
			explicit Asymmetric(const Algorithm::Asymmetric& algorithm, const KeyPair& key_pair) noexcept;

			/**
			 * @brief Constructs an Asymmetric instance with a specified algorithm and key pair (move version).
			 * @param algorithm The asymmetric encryption algorithm to use.
			 * @param key_pair The key pair to use for encryption and decryption (rvalue reference).
			 */
			explicit Asymmetric(const Algorithm::Asymmetric& algorithm, KeyPair&& key_pair) noexcept;

			/**
			 * @brief Copy constructor for the Asymmetric class.
			 * @param crypter The Asymmetric instance to copy.
			 */
			Asymmetric(const Asymmetric& crypter) 						= default;

			/**
			 * @brief Move constructor for the Asymmetric class.
			 * @param crypter The Asymmetric instance to move.
			 */
			Asymmetric(Asymmetric&& crypter) noexcept 					= default;

			/**
			 * @brief Destructor for the Asymmetric class.
			 */
			~Asymmetric() noexcept override 							= default;

			/**
			 * @brief Copy assignment operator for the Asymmetric class.
			 * @param crypter The Asymmetric instance to copy.
			 * @return A reference to the updated Asymmetric instance.
			 */
			Asymmetric& operator=(const Asymmetric& crypter) 			= default;

			/**
			 * @brief Move assignment operator for the Asymmetric class.
			 * @param crypter The Asymmetric instance to move.
			 * @return A reference to the updated Asymmetric instance.
			 */
			Asymmetric& operator=(Asymmetric&& crypter) noexcept 		= default;

			/**
			 * @brief Encrypts a string input using the asymmetric encryption algorithm.
			 * @param input The string to encrypt.
			 * @return An Expected containing the encrypted string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception> 							Encrypt(const std::string& input) const noexcept override;

			/**
			 * @brief Encrypts a buffer using the asymmetric encryption algorithm.
			 * @param buffer The buffer to encrypt.
			 * @return An Expected containing the encrypted buffer or an error.
			 */
			[[nodiscard]]
			Expected<Buffer::FIFO, Exception> 						Encrypt(const Buffer::FIFO& buffer) const noexcept override;

			/**
			 * @brief Encrypts data asynchronously using a Consumer/Producer model.
			 * @param consumer The Consumer buffer containing the input data.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			[[nodiscard]]
			Buffer::Consumer 											Encrypt(const Buffer::Consumer consumer) const noexcept override;

			/**
			 * @brief Decrypts a string input using the asymmetric encryption algorithm.
			 * @param input The string to decrypt.
			 * @return An Expected containing the decrypted string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception> 							Decrypt(const std::string& input) const noexcept override;

			/**
			 * @brief Decrypts a buffer using the asymmetric encryption algorithm.
			 * @param buffer The buffer to decrypt.
			 * @return An Expected containing the decrypted buffer or an error.
			 */
			[[nodiscard]]
			Expected<Buffer::FIFO, Exception> 						Decrypt(const Buffer::FIFO& buffer) const noexcept override;

			/**
			 * @brief Decrypts data asynchronously using a Consumer/Producer model.
			 * @param consumer The Consumer buffer containing the encrypted data.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			[[nodiscard]]
			Buffer::Consumer 											Decrypt(const Buffer::Consumer consumer) const noexcept override;

			/**
			 * @brief Returns the key pair associated with this Asymmetric instance.
			 * @return A reference to the key pair.
			 */
			[[nodiscard]]
			const KeyPair& 												KeyPair() const noexcept;

		private:
			Algorithm::Asymmetric m_algorithm; ///< The asymmetric encryption algorithm to use.
			class KeyPair m_keys;              ///< The key pair used for encryption/decryption.
	};
}