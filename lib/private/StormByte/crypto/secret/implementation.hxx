#pragma once

#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/visibility.h>

#include <string>
#include <eccrypto.h>

namespace StormByte::Crypto::Secret {
	// Agreement: derive shared secret using Agreement/Domain actor type.
	template<typename AgreementT, typename... CtorArgs>
	STORMBYTE_CRYPTO_PRIVATE std::optional<std::string> AgreementDeriveSharedSecret(const std::string& privateKeyBase64, const std::string& peerPublicKeyBase64, CtorArgs&&... args) noexcept {
		try {
			CryptoPP::SecByteBlock priv = KeyPair::DecodeSecBlockBase64(privateKeyBase64);
			CryptoPP::SecByteBlock pub = KeyPair::DecodeSecBlockBase64(peerPublicKeyBase64);

			AgreementT agr(std::forward<CtorArgs>(args)...);
			// If decoded sizes don't match the Agreement's raw key lengths,
			// attempt to handle ASN.1-encoded keys for specific agreement types
			if (priv.size() != agr.PrivateKeyLength() || pub.size() != agr.PublicKeyLength()) {
				// Special-case: ECDH with EC keys stored as ASN.1 (Base64 via SerializeKey)
				if constexpr (std::is_same_v<AgreementT, CryptoPP::ECDH<CryptoPP::ECP>::Domain>) {
					// Try to deserialize ASN.1 keys and extract raw private scalar and
					// uncompressed public point bytes expected by the Agreement.
					auto privKeyObj = KeyPair::DeserializeKey<CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey>(privateKeyBase64);
					auto pubKeyObj = KeyPair::DeserializeKey<CryptoPP::ECIES<CryptoPP::ECP>::PublicKey>(peerPublicKeyBase64);
					if (!privKeyObj || !pubKeyObj) {
						return std::nullopt;
					}
					size_t privLen = agr.PrivateKeyLength();
					size_t pubLen = agr.PublicKeyLength();
					CryptoPP::SecByteBlock privRaw(privLen), pubRaw(pubLen);
					CryptoPP::Integer d = privKeyObj->GetPrivateExponent();
					d.Encode(privRaw.data(), privLen);
					CryptoPP::ECP::Point Q = pubKeyObj->GetPublicElement();
					// encode uncompressed point: 0x04 || X || Y
					size_t coordLen = (pubLen - 1) / 2;
					pubRaw[0] = 0x04;
					Q.x.Encode(pubRaw.data() + 1, coordLen);
					Q.y.Encode(pubRaw.data() + 1 + coordLen, coordLen);
					priv = std::move(privRaw);
					pub = std::move(pubRaw);
					// Try both argument orders for Agreement::Agree (some domains differ)
					{
						CryptoPP::SecByteBlock secret(agr.AgreedValueLength());
						if (agr.Agree(secret, priv, pub)) {
							return KeyPair::EncodeSecBlockBase64(secret);
						}
						// Try swapped order
						CryptoPP::SecByteBlock secret2(agr.AgreedValueLength());
						if (agr.Agree(secret2, pub, priv)) {
							return KeyPair::EncodeSecBlockBase64(secret2);
						}
						return std::nullopt;
					}
					
				} else {
					return std::nullopt;
				}
			}
			CryptoPP::SecByteBlock secret(agr.AgreedValueLength());
			if (!agr.Agree(secret, pub, priv)) {
				return std::nullopt;
			}

			return KeyPair::EncodeSecBlockBase64(secret);
		} catch (const std::exception& e) {
			return std::nullopt;
		}
	}
}