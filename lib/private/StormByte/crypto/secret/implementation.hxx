#pragma once

#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <optional>
#include <string>
#include <eccrypto.h>

namespace StormByte::Crypto::Secret {

	/**
	 * @brief Derive a shared secret from a binary private key and a Base64 peer public key.
	 * @tparam AgreementT Crypto++ agreement/domain type (e.g. ECDH::Domain, x25519).
	 * @param privateKey Binary private key in @ref Password.
	 * @param peerPublicKeyBase64 Peer public key encoded as Base64.
	 * @param agr Agreement object already constructed by the caller.
	 * @return Shared secret as @ref Password, or nullopt on failure.
	 */
	template<typename AgreementT>
	STORMBYTE_CRYPTO_PRIVATE std::optional<Password> AgreementDeriveSharedSecret(
		const Password& privateKey,
		const std::string& peerPublicKeyBase64,
		AgreementT agr) noexcept
	{
		CryptoPP::SecByteBlock priv;
		CryptoPP::SecByteBlock pub;
		CryptoPP::SecByteBlock secret;
		try {
			const unsigned char* privData = Helpers::PasswordAccess::Data(privateKey);
			const std::size_t privSize = Helpers::PasswordAccess::Size(privateKey);
			if (!privData || privSize == 0)
				return std::nullopt;

			priv.Assign(privData, privSize);
			pub = KeyPair::DecodeSecBlockBase64(peerPublicKeyBase64);

			if (priv.size() != agr.PrivateKeyLength() || pub.size() != agr.PublicKeyLength()) {
				if constexpr (std::is_same_v<AgreementT, CryptoPP::ECDH<CryptoPP::ECP>::Domain>) {
					auto privKeyObj = KeyPair::DeserializeKey<CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey>(privateKey);
					auto pubKeyObj = KeyPair::DeserializeKey<CryptoPP::ECIES<CryptoPP::ECP>::PublicKey>(peerPublicKeyBase64);
					if (!privKeyObj || !pubKeyObj) {
						Helpers::SecureWipe(priv);
						Helpers::SecureWipe(pub);
						return std::nullopt;
					}

					const size_t privLen = agr.PrivateKeyLength();
					const size_t pubLen = agr.PublicKeyLength();
					CryptoPP::SecByteBlock privRaw(privLen);
					CryptoPP::SecByteBlock pubRaw(pubLen);

					CryptoPP::Integer d = privKeyObj->GetPrivateExponent();
					d.Encode(privRaw.data(), privLen);

					CryptoPP::ECP::Point Q = pubKeyObj->GetPublicElement();
					const size_t coordLen = (pubLen - 1) / 2;
					pubRaw[0] = 0x04;
					Q.x.Encode(pubRaw.data() + 1, coordLen);
					Q.y.Encode(pubRaw.data() + 1 + coordLen, coordLen);

					Helpers::SecureWipe(priv);
					Helpers::SecureWipe(pub);
					priv = std::move(privRaw);
					pub = std::move(pubRaw);

					secret.CleanNew(agr.AgreedValueLength());
					if (agr.Agree(secret, priv, pub)) {
						Password result(secret.data(), secret.size());
						Helpers::SecureWipe(priv);
						Helpers::SecureWipe(pub);
						Helpers::SecureWipe(secret);
						return result;
					}

					CryptoPP::SecByteBlock secret2(agr.AgreedValueLength());
					if (agr.Agree(secret2, pub, priv)) {
						Password result(secret2.data(), secret2.size());
						Helpers::SecureWipe(priv);
						Helpers::SecureWipe(pub);
						Helpers::SecureWipe(secret);
						Helpers::SecureWipe(secret2);
						return result;
					}

					Helpers::SecureWipe(priv);
					Helpers::SecureWipe(pub);
					Helpers::SecureWipe(secret);
					Helpers::SecureWipe(secret2);
					return std::nullopt;
				}

				Helpers::SecureWipe(priv);
				Helpers::SecureWipe(pub);
				return std::nullopt;
			}

			secret.CleanNew(agr.AgreedValueLength());
			if (!agr.Agree(secret, pub, priv)) {
				Helpers::SecureWipe(priv);
				Helpers::SecureWipe(pub);
				Helpers::SecureWipe(secret);
				return std::nullopt;
			}

			Password result(secret.data(), secret.size());
			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);
			Helpers::SecureWipe(secret);
			return result;
		} catch (...) {
			Helpers::SecureWipe(priv);
			Helpers::SecureWipe(pub);
			Helpers::SecureWipe(secret);
			return std::nullopt;
		}
	}
}
