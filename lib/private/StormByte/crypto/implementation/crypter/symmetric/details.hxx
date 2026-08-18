#pragma once

#include <StormByte/crypto/implementation/crypter/details.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <pwdbased.h>
#include <secblock.h>
#include <span>
#include <cstddef>

namespace StormByte::Crypto::Implementation::Crypter::Symmetric {
#ifdef STORMBYTE_CRYPTO_INSECURE_PBKDF2_ITERATIONS_FOR_CI
	inline constexpr unsigned int kPbkdf2Iterations = 1000;
#else
	inline constexpr unsigned int kPbkdf2Iterations = 600000;
#endif

	/**
	 * @brief Derive a key from a password using PBKDF2-HMAC.
	 * @param key  Pre-sized output key buffer.
	 * @param salt Salt bytes (already filled).
	 * @param password Password material.
	 * @return Value returned by Crypto++ DeriveKey, or 0 on failure.
	 */
	template<class CryptoHMAC>
	size_t DeriveKey(CryptoPP::SecByteBlock& key,
					const CryptoPP::SecByteBlock& salt,
					const Password& password) noexcept
	{
		try {
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoHMAC> pbkdf2;
			const unsigned char* pwdData = Helpers::PasswordAccess::Data(password);
			const std::size_t pwdSize = Helpers::PasswordAccess::Size(password);
			return pbkdf2.DeriveKey(
				key,
				key.size(),
				0,
				pwdData ? pwdData : reinterpret_cast<const uint8_t*>(""),
				pwdSize,
				salt,
				salt.size(),
				kPbkdf2Iterations
			);
		} catch (...) {
			return 0;
		}
	}

	template<typename CryptorT>
	auto SetKeyIVImpl(CryptorT& c,
					const CryptoPP::SecByteBlock& key, size_t keylen,
					const CryptoPP::SecByteBlock& iv, size_t ivlen, int)
		-> decltype(c.SetKeyWithIV(key, keylen, iv, ivlen), void())
	{
		c.SetKeyWithIV(key, keylen, iv, ivlen);
	}

	template<typename CryptorT>
	void SetKeyIVImpl(CryptorT& c,
					const CryptoPP::SecByteBlock& key, size_t keylen,
					const CryptoPP::SecByteBlock& iv, size_t ivlen, long)
	{
		c.SetKeyWithoutResync(key.data(), keylen, CryptoPP::g_nullNameValuePairs);
		c.Resync(iv.data(), static_cast<int>(ivlen));
	}

	template<typename CryptorT>
	void SetKeyIV(CryptorT& c,
				const CryptoPP::SecByteBlock& key, size_t keylen,
				const CryptoPP::SecByteBlock& iv, size_t ivlen)
	{
		SetKeyIVImpl(c, key, keylen, iv, ivlen, 0);
	}
}
