#pragma once

#include <StormByte/crypto/visibility.h>

#include <cstddef>
#include <memory>
#include <string>
#include <utility>

namespace StormByte::Crypto::Helpers {
	struct SecureContent;
	struct PasswordAccess;
}

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptography-related classes.
 */
namespace StormByte::Crypto {

	/**
	 * @class Password
	 * @brief Secure, reference-counted container for passwords and binary key material.
	 *
	 * @details
	 * Stores sensitive bytes inside a shared @ref Helpers::SecureContent with
	 * automatic wipe when the last owner is destroyed.
	 *
	 * - Copyable and movable (shared ownership of the same buffer).
	 * - No public access to the raw bytes (library code uses a private helper).
	 * - Binary constructors store the exact size; no trailing null is appended.
	 *
	 * Creating unmanaged @c std::string copies of the content is strongly
	 * discouraged and would bypass the secure lifecycle of this class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Password {
		public:
			/**
			 * @brief Construct from a @c std::string (copied byte-for-byte, then wiped).
			 * @param value Password characters. The parameter is securely wiped before return.
			 */
			explicit												Password(std::string value) noexcept;

			/**
			 * @brief Construct from a C string (copied byte-for-byte up to the terminator).
			 * @param value Null-terminated password. The pointed memory is not wiped.
			 */
			explicit												Password(const char* value) noexcept;

			/**
			 * @brief Construct from raw bytes (exact size, no null terminator added).
			 * @param data Pointer to the bytes (may be nullptr if size is 0).
			 * @param size Number of bytes to store.
			 */
																Password(const void* data, std::size_t size) noexcept;

			/**
			 * @brief Copy constructor.
			 * @param other The other Password to copy from (shares ownership).
			 */
																Password(const Password& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other The other Password to move from.
			 */
																Password(Password&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 * Wipes the underlying buffer when this is the last owner.
			 */
																~Password() = default;

			/**
			 * @brief Copy assignment operator.
			 * @param other The other Password to copy from.
			 * @return Reference to this Password.
			 */
			Password&											operator=(const Password& other) = default;

			/**
			 * @brief Move assignment operator.
			 * @param other The other Password to move from.
			 * @return Reference to this Password.
			 */
			Password&											operator=(Password&& other) noexcept = default;

			/**
			 * @brief Length of the stored material in bytes.
			 * @return Exact byte count (no implied null terminator).
			 */
			std::size_t											Size() const noexcept;

			/**
			 * @brief Check whether the password is empty.
			 * @return true if Size() is 0, false otherwise.
			 */
			bool												Empty() const noexcept;

			/**
			 * @brief Contextual conversion to bool.
			 * @return true if the password is not empty, false otherwise.
			 */
			explicit operator bool() const noexcept;

			/**
			 * @brief Constant-time equality comparison.
			 * @param other The other Password to compare with.
			 * @return true if both have the same length and content, false otherwise.
			 */
			bool												operator==(const Password& other) const noexcept;

			/**
			 * @brief Inequality comparison.
			 * @param other The other Password to compare with.
			 * @return true if not equal, false otherwise.
			 */
			bool												operator!=(const Password& other) const noexcept;

		private:
			friend struct Helpers::PasswordAccess;

			std::shared_ptr<Helpers::SecureContent>				m_data;	///< Shared secure storage
	};
}
