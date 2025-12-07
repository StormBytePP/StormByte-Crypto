#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;

ECDH::PointerType ECDH::Generate(unsigned short key_size) noexcept {
	CryptoPP::OID curve_oid;
	switch (key_size) {
		case 256:
			curve_oid = CryptoPP::ASN1::secp256r1();
			break;
		case 384:
			curve_oid = CryptoPP::ASN1::secp384r1();
			break;
		case 521:
			curve_oid = CryptoPP::ASN1::secp521r1();
			break;
		default:
			return nullptr;
	}


	try {
		// Generate an EC keypair and serialize as ASN.1 (Base64) like other key types
		ECIES::PrivateKey privateKey;
		privateKey.Initialize(RNG(), curve_oid);

		ECIES::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		if (!privateKey.Validate(RNG(), 3)) return nullptr;
		if (!publicKey.Validate(RNG(), 3)) return nullptr;

		return std::make_shared<ECDH>(
			SerializeKey<CryptoPP::ECIES<CryptoPP::ECP>::PublicKey>(publicKey),
			SerializeKey<CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey>(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}