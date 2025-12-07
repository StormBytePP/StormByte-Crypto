#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/implementation/encryption/ecdh.hxx>

#include <cryptlib.h>
#include <eccrypto.h>
#include <oids.h>
#include <base64.h>
#include <string>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	std::string SerializeKey(const CryptoPP::SecByteBlock& key) {
		std::string keyString;
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		encoder.Put(key.data(), key.size());
		encoder.MessageEnd();
		return keyString;
	}

	CryptoPP::SecByteBlock DeserializeKey(const std::string& keyString) {
		CryptoPP::SecByteBlock key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.resize(decoder.MaxRetrievable());
		decoder.Get(key.data(), key.size());
		return key;
	}
}

ExpectedKeyPair ECDH::GenerateKeyPair(const std::string& curveName) noexcept {
	try {
		// Select the curve
		CryptoPP::OID curve;
		if (curveName == "secp256r1") {
			curve = CryptoPP::ASN1::secp256r1();
		} else if (curveName == "secp384r1") {
			curve = CryptoPP::ASN1::secp384r1();
		} else if (curveName == "secp521r1") {
			curve = CryptoPP::ASN1::secp521r1();
		} else {
			return Unexpected(KeyPairException("Unknown curve name: {}", curveName));
		}

		// Initialize ECDH domain
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams(curve);
		CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdhDomain(ecParams);

		// Generate private and public keys
		CryptoPP::SecByteBlock privateKey(ecdhDomain.PrivateKeyLength());
		CryptoPP::SecByteBlock publicKey(ecdhDomain.PublicKeyLength());
		ecdhDomain.GenerateKeyPair(RNG(), privateKey, publicKey);

		// Serialize keys
		std::string serializedPrivateKey = SerializeKey(privateKey);
		std::string serializedPublicKey = SerializeKey(publicKey);

		return KeyPair{
			.Private = serializedPrivateKey,
			.Public = serializedPublicKey,
		};
	} catch (const std::exception& e) {
		return Unexpected(KeyPairException("ECDH key generation failed: {}", e.what()));
	}
}

ExpectedCryptoString ECDH::DeriveSharedSecret(const std::string& privateKey, const std::string& peerPublicKey) noexcept {
	try {
		// Deserialize keys
		CryptoPP::SecByteBlock privateKeyBlock = DeserializeKey(privateKey);
		CryptoPP::SecByteBlock peerPublicKeyBlock = DeserializeKey(peerPublicKey);

		// Validate deserialized keys
		if (privateKeyBlock.empty()) {
			return Unexpected(SecretException("Invalid private key: deserialization failed or key is empty"));
		}
		if (peerPublicKeyBlock.empty()) {
			return Unexpected(SecretException("Invalid public key: deserialization failed or key is empty"));
		}

		// Select the curve
		///< @todo Make curve selection dynamic based on key parameters
		CryptoPP::OID curve = CryptoPP::ASN1::secp256r1();

		// Initialize ECDH domain
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams(curve);
		CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdhDomain(ecParams);

		// Validate key lengths
		if (privateKeyBlock.size() != ecdhDomain.PrivateKeyLength()) {
			return Unexpected(SecretException("Invalid private key length"));
		}
		if (peerPublicKeyBlock.size() != ecdhDomain.PublicKeyLength()) {
			return Unexpected(SecretException("Invalid public key length"));
		}

		// Derive the shared secret
		CryptoPP::SecByteBlock sharedSecret(ecdhDomain.AgreedValueLength());
		if (!ecdhDomain.Agree(sharedSecret, privateKeyBlock, peerPublicKeyBlock)) {
			return Unexpected(SecretException("Failed to derive shared secret"));
		}

		// Serialize the shared secret
		std::string serializedSharedSecret = SerializeKey(sharedSecret);
		return serializedSharedSecret;
	} catch (const std::exception& e) {
		return Unexpected(SecretException("ECDH shared secret derivation failed: {}", e.what()));
	}
}