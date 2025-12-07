#pragma once

#include <StormByte/crypto/crypter/generic.hxx>

#include <string>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class Symmetric
	 * @brief A generic symmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Symmetric: public Generic {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Symmetric crypter to copy from.
			 */
			Symmetric(const Symmetric& other)					= default;

			/**
			 * @brief Move constructor
			 * @param other The other Symmetric crypter to move from.
			 */
			Symmetric(Symmetric&& other) noexcept				= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Symmetric() noexcept 						= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Symmetric crypter to copy from.
			 * @return Reference to this Symmetric crypter.
			 */
			Symmetric& operator=(const Symmetric& other)		= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Symmetric crypter to move from.
			 * @return Reference to this Symmetric crypter.
			 */
			Symmetric& operator=(Symmetric&& other) noexcept	= default;

			/**
			 * @brief Gets the password used for symmetric encryption.
			 * @return The password.
			 */
			inline const std::string&							Password() const noexcept {
				return m_password;
			}

			/**
			 * @brief Generates a random password for symmetric encryption.
			 * @param length The length of the password to generate.
			 * @return A random password string.
			 */
			static std::string 									RandomPassword(size_t length = 32) noexcept;

		protected:
			std::string m_password;								///< The password used for symmetric encryption

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 */
			inline 												Symmetric(enum Type type, const std::string& password):
			Generic(type), m_password(password) {}
	};

	/**
	 * @brief Creates a symmetric crypter based on the type.
	 * @param type The type of crypter.
	 * @param password The password to use for the crypter.
	 * @return A pointer to the created symmetric crypter.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType				Create(enum Type type, const std::string& password) noexcept;
}