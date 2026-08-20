#pragma once

#include <StormByte/crypto/crypter/generic.hxx>
#include <StormByte/crypto/password.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class Symmetric
	 * @brief A generic symmetric crypter class.
	 *
	 * Stores the encryption password as a @ref StormByte::Crypto::Password
	 * so that all copies share the same underlying buffer and the memory is
	 * securely wiped when the last owner is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Symmetric: public Generic {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Symmetric crypter to copy from.
			 */
			Symmetric(const Symmetric& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other Symmetric crypter to move from.
			 */
			Symmetric(Symmetric&& other) noexcept = default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Symmetric() noexcept override;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Symmetric crypter to copy from.
			 * @return Reference to this Symmetric crypter.
			 */
			Symmetric& operator=(const Symmetric& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Symmetric crypter to move from.
			 * @return Reference to this Symmetric crypter.
			 */
			Symmetric& operator=(Symmetric&& other) noexcept = default;

			/**
			 * @brief Gets the password used for symmetric encryption.
			 * @return A const reference to the stored @ref Password.
			 * @note The returned object shares ownership of the underlying data.
			 */
			inline const class Password& Password() const noexcept {
				return m_password;
			}

			/**
			 * @brief Generates a random password for symmetric encryption.
			 * @param length Number of random bytes to generate.
			 * @return A @ref Password containing raw random bytes (not text/hex).
			 */
			static class Password RandomPassword(size_t length = 32) noexcept;

		protected:
			class Password m_password;	///< The password used for symmetric encryption

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 * @param password The password to use for encryption/decryption.
			 */
			inline Symmetric(enum Type type, class Password password):
				Generic(type), m_password(std::move(password)) {}
	};

	/**
	 * @brief Creates a symmetric crypter based on the type.
	 * @param type The type of crypter.
	 * @param password The password to use for the crypter.
	 * @return A pointer to the created symmetric crypter, or nullptr on failure.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, class Password password) noexcept;
}
