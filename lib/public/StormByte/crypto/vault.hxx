#pragma once

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/exception.hxx>

#include <string>
#include <unordered_map>
#include <utility>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptography-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Vault
	 * @brief Secure container for named passwords.
	 *
	 * Owns a collection of @ref Password objects and automatically
	 * releases them (triggering secure wipe) on destruction or when
	 * Clear() / Remove() is called.
	 * The class is non-copyable and only movable.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Vault {
		public:
			/**
			 * @brief Default constructor.
			 * Creates an empty vault.
			 */
			Vault()													= default;

			/**
			 * @brief Copy constructor (deleted).
			 * Copying is disabled to prevent accidental duplication of the vault.
			 */
			Vault(const Vault&)										= delete;

			/**
			 * @brief Move constructor.
			 * @param other The vault to move from.
			 */
			Vault(Vault&& other) noexcept;

			/**
			 * @brief Destructor.
			 * Releases all stored passwords (secure wipe is performed by @ref Password).
			 */
			~Vault() noexcept;

			/**
			 * @brief Copy assignment operator (deleted).
			 */
			Vault& operator=(const Vault&)							= delete;

			/**
			 * @brief Move assignment operator.
			 * @param other The vault to move from.
			 * @return Reference to this vault.
			 */
			Vault& operator=(Vault&& other) noexcept;

			/**
			 * @brief Store (or overwrite) a named password.
			 * @param name     Identifier for the password.
			 * @param password The password to store (copied / shared).
			 */
			void 													Store(std::string name, Password password) noexcept;

			/**
			 * @brief Retrieve a password by name.
			 * @param name Identifier of the password to retrieve.
			 * @return Expected containing a @ref Password on success,
			 *         or an error if the name does not exist.
			 * @note The returned @ref Password shares ownership of the
			 *       underlying data (cheap copy).
			 */
			ExpectedPassword 										Get(const std::string& name) const noexcept;

			/**
			 * @brief Check whether a named password exists.
			 * @param name Identifier to look for.
			 * @return true if the password exists, false otherwise.
			 */
			bool 													Contains(const std::string& name) const noexcept;

			/**
			 * @brief Remove a named password.
			 * @param name Identifier of the password to remove.
			 */
			void 													Remove(const std::string& name) noexcept;

			/**
			 * @brief Remove all stored passwords.
			 */
			void 													Clear() noexcept;

			/**
			 * @brief Get the number of stored passwords.
			 * @return The number of passwords currently stored in the vault.
			 */
			std::size_t 											Size() const noexcept;

			/**
			 * @brief Check whether the vault is empty.
			 * @return true if no passwords are stored, false otherwise.
			 */
			bool 													Empty() const noexcept;

		private:
			std::unordered_map<std::string, Password> m_passwords;	///< Named passwords storage
	};
}
