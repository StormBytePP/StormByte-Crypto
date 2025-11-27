#include <StormByte/crypto/implementation/encryption/ecdh.hxx>

#include <cryptlib.h>
#include <eccrypto.h>
#include <osrng.h>
#include <oids.h>
#include <base64.h>
#include <string>
#include <future>

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
		CryptoPP::AutoSeededRandomPool rng;

		// Select the curve
		CryptoPP::OID curve;
		if (curveName == "secp256r1") {
			curve = CryptoPP::ASN1::secp256r1();
		} else if (curveName == "secp384r1") {
			curve = CryptoPP::ASN1::secp384r1();
		} else if (curveName == "secp521r1") {
			curve = CryptoPP::ASN1::secp521r1();
		} else {
			return StormByte::Unexpected<Exception>("Unknown curve name: " + curveName);
		}

		// Initialize ECDH domain
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams(curve);
		CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdhDomain(ecParams);

		// Generate private and public keys
		CryptoPP::SecByteBlock privateKey(ecdhDomain.PrivateKeyLength());
		CryptoPP::SecByteBlock publicKey(ecdhDomain.PublicKeyLength());
		ecdhDomain.GenerateKeyPair(rng, privateKey, publicKey);

		// Serialize keys
		std::string serializedPrivateKey = SerializeKey(privateKey);
		std::string serializedPublicKey = SerializeKey(publicKey);

		return KeyPair{
			.Private = serializedPrivateKey,
			.Public = serializedPublicKey,
		};
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("ECDH key generation failed: " + std::string(e.what()));
	}
}

ExpectedCryptoString ECDH::DeriveSharedSecret(const std::string& privateKey, const std::string& peerPublicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize keys
		CryptoPP::SecByteBlock privateKeyBlock = DeserializeKey(privateKey);
		CryptoPP::SecByteBlock peerPublicKeyBlock = DeserializeKey(peerPublicKey);

		// Validate deserialized keys
		if (privateKeyBlock.empty()) {
			return StormByte::Unexpected<Exception>("Invalid private key: deserialization failed or key is empty");
		}
		if (peerPublicKeyBlock.empty()) {
			return StormByte::Unexpected<Exception>("Invalid public key: deserialization failed or key is empty");
		}

		// Select the curve
		CryptoPP::OID curve = CryptoPP::ASN1::secp256r1();

		// Initialize ECDH domain
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ecParams(curve);
		CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdhDomain(ecParams);

		// Validate key lengths
		if (privateKeyBlock.size() != ecdhDomain.PrivateKeyLength()) {
			return StormByte::Unexpected<Exception>("Invalid private key length");
		}
		if (peerPublicKeyBlock.size() != ecdhDomain.PublicKeyLength()) {
			return StormByte::Unexpected<Exception>("Invalid public key length");
		}

		// Derive the shared secret
		CryptoPP::SecByteBlock sharedSecret(ecdhDomain.AgreedValueLength());
		if (!ecdhDomain.Agree(sharedSecret, privateKeyBlock, peerPublicKeyBlock)) {
			return StormByte::Unexpected<Exception>("Failed to derive shared secret");
		}

		// Serialize the shared secret
		std::string serializedSharedSecret = SerializeKey(sharedSecret);
		return serializedSharedSecret;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("ECDH shared secret derivation failed: " + std::string(e.what()));
	}
}