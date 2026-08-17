#pragma once

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/helpers/secure_content.hxx>

#include <cstddef>

/**
 * @namespace Helpers
 * @brief Private helpers for the Crypto module (headers are not installed).
 */
namespace StormByte::Crypto::Helpers {

	/**
	 * @struct PasswordAccess
	 * @brief Internal read access to @ref StormByte::Crypto::Password bytes.
	 *
	 * Only for library implementation. Not part of the public API.
	 */
	struct PasswordAccess {
		/**
		 * @brief Pointer to the password/key bytes.
		 * @param password The password instance.
		 * @return Pointer to the data, or nullptr if empty/invalid.
		 */
		static const unsigned char* Data(const Password& password) noexcept {
			return password.m_data ? password.m_data->Data() : nullptr;
		}

		/**
		 * @brief Exact byte length of the stored material.
		 * @param password The password instance.
		 * @return Size in bytes.
		 */
		static std::size_t Size(const Password& password) noexcept {
			return password.m_data ? password.m_data->Size() : 0;
		}
	};
}
