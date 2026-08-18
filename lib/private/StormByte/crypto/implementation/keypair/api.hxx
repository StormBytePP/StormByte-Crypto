#pragma once

#include <StormByte/crypto/implementation/keypair/details.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/visibility.h>

#include <base64.h>
#include <filters.h>
#include <queue.h>
#include <memory>
#include <optional>
#include <string>

namespace StormByte::Crypto::Implementation::KeyPair {
	/**
	 * @brief Serialize a Crypto++ key to Base64 (public material).
	 */
	template<typename KeyT>
	std::string SerializeKey(const KeyT& key) noexcept
	{
		try {
			std::string keyString;
			CryptoPP::ByteQueue queue;
			key.Save(queue);
			CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false);
			queue.CopyTo(encoder);
			encoder.MessageEnd();
			return keyString;
		} catch (...) {
			return {};
		}
	}

	/**
	 * @brief Serialize a Crypto++ key to raw ASN.1/DER bytes for secure storage.
	 * @return Password holding the binary key material, or empty Password on failure.
	 */
	template<typename KeyT>
	Password SerializeKeyBinary(const KeyT& key) noexcept
	{
		try {
			CryptoPP::ByteQueue queue;
			key.Save(queue);
			const size_t n = queue.CurrentSize();
			CryptoPP::SecByteBlock der(n);
			queue.Get(der.data(), der.size());
			Password result(der.data(), der.size());
			Helpers::SecureWipe(der);
			return result;
		} catch (...) {
			return Password(static_cast<const void*>(nullptr), 0);
		}
	}

	/**
	 * @brief Deserialize a key from Base64 (public keys).
	 */
	template<typename KeyT>
	std::shared_ptr<KeyT> DeserializeKey(const std::string& keyString) noexcept
	{
		try {
			KeyT key;
			CryptoPP::ByteQueue queue;
			CryptoPP::StringSource ss(
				keyString, true,
				new CryptoPP::Base64Decoder(new CryptoPP::Redirector(queue)));
			key.Load(queue);
			return std::make_shared<KeyT>(std::move(key));
		} catch (...) {
			return nullptr;
		}
	}

	/**
	 * @brief Deserialize a key from raw ASN.1/DER bytes (private keys in Password).
	 */
	template<typename KeyT>
	std::shared_ptr<KeyT> DeserializeKey(const Password& keyBinary) noexcept
	{
		try {
			const unsigned char* data = Helpers::PasswordAccess::Data(keyBinary);
			const std::size_t n = Helpers::PasswordAccess::Size(keyBinary);
			if (!data || n == 0)
				return nullptr;

			KeyT key;
			CryptoPP::ByteQueue queue;
			queue.Put(data, n);
			key.Load(queue);
			return std::make_shared<KeyT>(std::move(key));
		} catch (...) {
			return nullptr;
		}
	}

	/**
	 * @brief Deserialize from optional binary private key.
	 */
	template<typename KeyT>
	std::shared_ptr<KeyT> DeserializeKey(const std::optional<Password>& keyBinary) noexcept
	{
		if (!keyBinary.has_value())
			return nullptr;
		return DeserializeKey<KeyT>(*keyBinary);
	}

	/**
	 * @brief Generate an Agreement/Domain keypair; private stays binary in Password.
	 */
	template<typename KeyPairT, typename AgreementT, typename... CtorArgs>
	std::shared_ptr<KeyPairT> AgreementGenerateKeyPair(CtorArgs&&... args) noexcept
	{
		try {
			AgreementT agr(std::forward<CtorArgs>(args)...);
			CryptoPP::SecByteBlock priv(agr.PrivateKeyLength());
			CryptoPP::SecByteBlock pub(agr.PublicKeyLength());
			agr.GenerateKeyPair(RNG(), priv, pub);

			auto pubStr = EncodeSecBlockBase64(pub);
			Password privPwd = PasswordFromSecBlock(priv);
			Helpers::SecureWipe(pub);

			return std::make_shared<KeyPairT>(std::move(pubStr), std::move(privPwd));
		} catch (...) {
			return nullptr;
		}
	}
}
