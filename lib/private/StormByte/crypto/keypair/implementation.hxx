#pragma once

#include <StormByte/crypto/random.hxx>

#include <base64.h>
#include <memory>
#include <optional>
#include <queue.h>
#include <string>

namespace StormByte::Crypto::KeyPair {
	template<typename KeyT>
	STORMBYTE_CRYPTO_PRIVATE std::string SerializeKey(const KeyT& key) noexcept {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	template<typename KeyT>
	STORMBYTE_CRYPTO_PRIVATE std::shared_ptr<KeyT> DeserializeKey(const std::string& keyString) noexcept {
		try {
			KeyT key;
			// Decode base64 into a ByteQueue then load the key from the queue
			CryptoPP::ByteQueue queue;
			CryptoPP::StringSource ss(keyString, true, new CryptoPP::Base64Decoder(new CryptoPP::Redirector(queue)));
			key.Load(queue);
			return std::make_shared<KeyT>(std::move(key));
		} catch (...) {
			return nullptr;
		}
	}

	template<typename KeyT>
	STORMBYTE_CRYPTO_PRIVATE std::shared_ptr<KeyT> DeserializeKey(const std::optional<std::string>& keyString) noexcept {
		if (!keyString.has_value())
			return nullptr;
		return DeserializeKey<KeyT>(*keyString);
	}

	STORMBYTE_CRYPTO_PRIVATE std::string EncodeSecBlockBase64(const CryptoPP::SecByteBlock& b) noexcept;
	STORMBYTE_CRYPTO_PRIVATE CryptoPP::SecByteBlock DecodeSecBlockBase64(const std::string& s) noexcept;

	// Agreement: generate keypair using an Agreement/Domain actor type.
	template<typename KeyPairT, typename AgreementT, typename... CtorArgs>
	STORMBYTE_CRYPTO_PRIVATE std::shared_ptr<KeyPairT> AgreementGenerateKeyPair(CtorArgs&&... args) noexcept {
		try {
			AgreementT agr(std::forward<CtorArgs>(args)...);
			auto privLen = agr.PrivateKeyLength();
			auto pubLen = agr.PublicKeyLength();
			CryptoPP::SecByteBlock priv(privLen), pub(pubLen);
			agr.GenerateKeyPair(RNG(), priv, pub);
			return std::make_shared<KeyPairT>(
					EncodeSecBlockBase64(priv),
					EncodeSecBlockBase64(pub)
				);
		} catch (...) {
			return nullptr;
		}
	}
}